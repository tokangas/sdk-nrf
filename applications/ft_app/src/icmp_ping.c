/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdio.h>
#include <shell/shell.h>

#include <modem/modem_info.h>
#include <net/socket.h>
#include <nrf_socket.h>

#define INVALID_SOCKET		-1
#define ICMP_MAX_URL		128
#define ICMP_MAX_LEN		512

#define ICMP			0x01
#define ICMP_ECHO_REQ		0x08
#define ICMP_ECHO_REP		0x00
#define IP_PROTOCOL_POS		0x09

/**@ ICMP Ping command arguments */
static struct ping_argv_t {
	struct addrinfo *src;
	struct addrinfo *dest;
	int len;
	int waitms;
	int count;
	int interval;
} ping_argv;

/* global variable defined in different files */
extern struct modem_param_info modem_param;
extern char rsp_buf[CONFIG_AT_CMD_RESPONSE_MAX_LEN];
/*

struct zsock_addrinfo {
	struct zsock_addrinfo *ai_next;
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;

	struct sockaddr _ai_addr;
	char _ai_canonname[DNS_MAX_NAME_SIZE + 1];
};
*/
static char *util_inet_ntoa(const struct sockaddr *addr)
{
	static char buf[NET_IPV6_ADDR_LEN];

	if (addr->sa_family == AF_INET6) {
		return net_addr_ntop(AF_INET6, &net_sin6(addr)->sin6_addr,
				     buf, sizeof(buf));
	}

	if (addr->sa_family == AF_INET) {
		return net_addr_ntop(AF_INET, &net_sin(addr)->sin_addr,
				     buf, sizeof(buf));
	}

	//LOG_ERR("Unknown IP address family:%d", addr->sa_family);
	strcpy(buf, "junk");
	return buf;
}
static inline void setip(u8_t *buffer, u32_t ipaddr)
{
	buffer[0] = ipaddr & 0xFF;
	buffer[1] = (ipaddr >> 8) & 0xFF;
	buffer[2] = (ipaddr >> 16) & 0xFF;
	buffer[3] = ipaddr >> 24;
}

static u16_t check_ics(const u8_t *buffer, int len)
{
	const u32_t *ptr32 = (const u32_t *)buffer;
	u32_t hcs = 0;
	const u16_t *ptr16;

	for (int i = len / 4; i > 0; i--) {
		u32_t s = *ptr32++;

		hcs += s;
		if (hcs < s) {
			hcs++;
		}
	}

	ptr16 = (const u16_t *)ptr32;

	if (len & 2) {
		u16_t s = *ptr16++;

		hcs += s;
		if (hcs < s) {
			hcs++;
		}
	}

	if (len & 1) {
		const u8_t *ptr8 = (const u8_t *)ptr16;
		u8_t s = *ptr8;

		hcs += s;
		if (hcs < s) {
			hcs++;
		}
	}

	while (hcs > 0xFFFF) {
		hcs = (hcs & 0xFFFF) + (hcs >> 16);
	}

	return ~hcs;    /* One's complement */
}

static void calc_ics(u8_t *buffer, int len, int hcs_pos)
{
	u16_t *ptr_hcs = (u16_t *)(buffer + hcs_pos);
	*ptr_hcs = 0;   /* Clear checksum before calculation */
	u16_t hcs;

	hcs = check_ics(buffer, len);
	*ptr_hcs = hcs;
}

static u32_t send_ping_wait_reply(const struct shell *shell)
{
	static u8_t seqnr;
	u16_t total_length;
	u8_t ip_buf[NET_IPV4_MTU];
	u8_t *data = NULL;
	static s64_t start_t, delta_t;
	const u8_t header_len = 20;
	int pllen, len;
	const u16_t icmp_hdr_len = 8;
	struct sockaddr_in *sa;
	struct nrf_pollfd fds[1];
	int fd;
	int ret;
	int hcs;
	int plseqnr;

	/* Generate IPv4 ICMP EchoReq */
	total_length = ping_argv.len + header_len + icmp_hdr_len;
	memset(ip_buf, 0x00, header_len);

	/* IPv4 header */
	ip_buf[0] = (4 << 4) + (header_len / 4); /* Version & header length */
	ip_buf[1] = 0x00;                        /* Type of service */
	ip_buf[2] = total_length >> 8;           /* Total length */
	ip_buf[3] = total_length & 0xFF;         /* Total length */
	ip_buf[4] = 0x00;                        /* Identification */
	ip_buf[5] = 0x00;                        /* Identification */
	ip_buf[6] = 0x00;                        /* Flags & fragment offset */
	ip_buf[7] = 0x00;                        /* Flags & fragment offset */
	ip_buf[8] = 64;                          /* TTL */
	ip_buf[9] = ICMP;                        /* Protocol */
	/* ip_buf[10..11] = ICS, calculated later */

	sa = (struct sockaddr_in *)ping_argv.src->ai_addr;
	setip(ip_buf+12, sa->sin_addr.s_addr);     /* Source */
	sa = (struct sockaddr_in *)ping_argv.dest->ai_addr;
	setip(ip_buf+16, sa->sin_addr.s_addr);     /* Destination */

	calc_ics(ip_buf, header_len, 10);

	/* ICMP header */
	data = ip_buf + header_len;
	data[0] = ICMP_ECHO_REQ;                 /* Type (echo req) */
	data[1] = 0x00;                          /* Code */
	/* data[2..3] = checksum, calculated later */
	data[4] = 0x00;                         /* Identifier */
	data[5] = 0x00;                         /* Identifier */
	data[6] = seqnr >> 8;                   /* seqnr */
	data[7] = ++seqnr;                      /* seqr */

	/* Payload */
	for (int i = 8; i < total_length - header_len; i++) {
	    data[i] = (i + seqnr) % 10 + '0';
	}

	/* ICMP CRC */
	calc_ics(data, total_length - header_len, 2);

	/* Send the ping */
	errno = 0;
	delta_t = 0;
	start_t = k_uptime_get();

	fd = nrf_socket(NRF_AF_PACKET, NRF_SOCK_RAW, 0);
	if (fd < 0) {
	    shell_print(shell, "socket() failed: (%d)", -errno);
	    return (u32_t)delta_t;
	}

	ret = nrf_send(fd, ip_buf, total_length, 0);
	if (ret <= 0) {
	    shell_print(shell, "nrf_send() failed: (%d)", -errno);
	    goto close_end;
	}

	fds[0].fd = fd;
	fds[0].events = NRF_POLLIN;
	ret = nrf_poll(fds, 1, ping_argv.waitms);
	if (ret <= 0) {
	    shell_print(shell, "nrf_poll() failed: (%d) (%d)", -errno, ret);
	    goto close_end;
	}

	/* receive response */
	do {
		len = nrf_recv(fd, ip_buf, NET_IPV4_MTU, 0);
		if (len <= 0) {
			shell_print(shell, "nrf_recv() failed: (%d) (%d)", -errno, len);
			goto close_end;
		}
		if (len < header_len) {
			/* Data length error, ignore silently */
			shell_print(shell, "nrf_recv() wrong data (%d)", len);
			continue;
		}
		if (ip_buf[IP_PROTOCOL_POS] != ICMP) {
			/* Not ipv4 echo reply, ignore silently */
			continue;
		}
		break;
	} while (1);

	delta_t = k_uptime_delta(&start_t);

	/* Check ICMP HCS */
	hcs = check_ics(data, len - header_len);
	if (hcs != 0) {
		shell_print(shell, "HCS error %d", hcs);
		delta_t = 0;
		goto close_end;
	}
	/* Payload length */
	pllen = (ip_buf[2] << 8) + ip_buf[3];

	/* Check seqnr and length */
	plseqnr = data[7];
	if (plseqnr != seqnr) {
		shell_print(shell, "error sequence numbers %d %d", plseqnr, seqnr);
		delta_t = 0;
		goto close_end;
	}
	if (pllen != len) {
		shell_print(shell, "error length %d %d", pllen, len);
		delta_t = 0;
		goto close_end;
	}

	/* Result */
	sprintf(rsp_buf, "PING results: time=%d.%03dsecs\r\n",
		(u32_t)(delta_t)/1000,
		(u32_t)(delta_t)%1000);
	shell_print_stream(shell, rsp_buf, strlen(rsp_buf));

close_end:
	(void)nrf_close(fd);
	return (u32_t)delta_t;
}

int icmp_ping_start(const struct shell *shell, const char *target_name)
{
    shell_print(shell,"initiating ping to: %s", target_name);
 
    int length, waittime, count, interval;
    int st;
    struct addrinfo *res;
    int addr_len;

 #ifdef RM_JH
    if (length > ICMP_MAX_LEN) {
        LOG_ERR("Payload size exceeds limit");
        return -1;
    }
 #endif

    st = modem_info_params_get(&modem_param);
    if (st < 0) {
        shell_print(shell, "Unable to obtain modem parameters (%d)", st);
        return -1;
    }
    /* Check network connection status by checking local IP address */
    addr_len = strlen(modem_param.network.ip_address.value_string);
    if (addr_len == 0) {
        shell_print(shell,"\nLTE not connected yet");
        return -1;
    }
    st = getaddrinfo(modem_param.network.ip_address.value_string,
            NULL, NULL, &res);
    if (st != 0) {
        shell_print(shell, "getaddrinfo(src) error: %d", st);
        return -st;
    }
    ping_argv.src = res;

    /* Get destination */
    res = NULL;
    st = getaddrinfo(target_name, NULL, NULL, &res);
    if (st != 0) {
        shell_print(shell, "getaddrinfo(dest) error: %d", st);
        shell_print(shell, "Cannot resolve remote host\r\n");
        freeaddrinfo(ping_argv.src);
        return -st;
    }
    ping_argv.dest = res;

    if (ping_argv.src->ai_family != ping_argv.dest->ai_family) {
        shell_print(shell, "Source/Destination address family error");
        freeaddrinfo(ping_argv.dest);
        freeaddrinfo(ping_argv.src);
        return -1;
    }
    else {
        struct sockaddr *sa;
        sa = ping_argv.src->ai_addr;
        shell_print(shell, "Source IP addr: %s", util_inet_ntoa(sa));
        sa = ping_argv.dest->ai_addr; 
        shell_print(shell, "Destination IP addr: %s",  util_inet_ntoa(sa)); 
    }

    ping_argv.len = length;
    ping_argv.waitms = 3000; //TODO: waittime;
    ping_argv.count = 1;		/* default 1 */
    ping_argv.interval = 1000;	/* default 1s */
    if (count > 0) {
        ping_argv.count = count;
    }
    if (interval > 0) {
        ping_argv.interval = interval;
    }

    //k_work_submit_to_queue(&slm_work_q, &my_work);
    (void)send_ping_wait_reply(shell);
    return 0;
}

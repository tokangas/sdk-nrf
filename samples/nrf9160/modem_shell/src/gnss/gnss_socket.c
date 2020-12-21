/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <shell/shell.h>
#include <nrf_socket.h>

#include "gnss.h"

#define GNSS_THREAD_STACK_SIZE 2048
#define GNSS_THREAD_PRIORITY 5 /* TODO: Check priority */

extern const struct shell *gnss_shell_global;

static int fd = -1;

/* Default output configuration */
uint8_t pvt_output_level = 2;
uint8_t nmea_output_level = 0;
uint8_t event_output_level = 0;

K_SEM_DEFINE(gnss_sem, 0, 1);

static void print_pvt_flags(nrf_gnss_pvt_data_frame_t *pvt)
{
	shell_print(gnss_shell_global, "\nFix valid:          %s",
		(pvt->flags & NRF_GNSS_PVT_FLAG_FIX_VALID_BIT) == NRF_GNSS_PVT_FLAG_FIX_VALID_BIT ? "true" : "false");
	shell_print(gnss_shell_global, "Leap second valid:  %s",
		(pvt->flags & NRF_GNSS_PVT_FLAG_LEAP_SECOND_VALID) == NRF_GNSS_PVT_FLAG_LEAP_SECOND_VALID ? "true" : "false");
	shell_print(gnss_shell_global, "Sleep between PVT:  %s",
		(pvt->flags & NRF_GNSS_PVT_FLAG_SLEEP_BETWEEN_PVT) == NRF_GNSS_PVT_FLAG_SLEEP_BETWEEN_PVT ? "true" : "false");
	shell_print(gnss_shell_global, "Deadline missed:    %s",
		(pvt->flags & NRF_GNSS_PVT_FLAG_DEADLINE_MISSED) == NRF_GNSS_PVT_FLAG_DEADLINE_MISSED ? "true" : "false");
	shell_print(gnss_shell_global, "Insuf. time window: %s\n",
		(pvt->flags & NRF_GNSS_PVT_FLAG_NOT_ENOUGH_WINDOW_TIME) == NRF_GNSS_PVT_FLAG_NOT_ENOUGH_WINDOW_TIME ? "true" : "false");

}

static void print_pvt(nrf_gnss_pvt_data_frame_t *pvt)
{
	char output_buffer[256];

        if (pvt_output_level == 0) {
                return;
        }

        print_pvt_flags(pvt);

	if ((pvt->flags & NRF_GNSS_PVT_FLAG_FIX_VALID_BIT) == NRF_GNSS_PVT_FLAG_FIX_VALID_BIT) {
		shell_print(gnss_shell_global, "Time:      %02d.%02d.%04d %02d:%02d:%02d.%03d",
			    pvt->datetime.day,
			    pvt->datetime.month,
			    pvt->datetime.year,
			    pvt->datetime.hour,
			    pvt->datetime.minute,
			    pvt->datetime.seconds,
			    pvt->datetime.ms);
		sprintf(output_buffer,
			"Latitude:  %f\n"
			"Longitude: %f\n"
			"Altitude:  %.1f m\n"
			"Accuracy:  %.1f m\n"
			"Speed:     %.1f m/s\n"
			"Heading:   %.1f deg\n"
			"PDOP:      %.1f\n"
			"HDOP:      %.1f\n"
			"VDOP:      %.1f\n"
			"TDOP:      %.1f",
			pvt->latitude,
			pvt->longitude,
			pvt->altitude,
			pvt->accuracy,
			pvt->speed,
			pvt->heading,
			pvt->pdop,
			pvt->hdop,
			pvt->vdop,
			pvt->tdop);
		shell_print(gnss_shell_global, "%s", output_buffer);
	}

	if (pvt_output_level < 2) {
		return;
	}

	/* SV data */
	for (int i = 0; i < NRF_GNSS_MAX_SATELLITES; i++) {
		if (pvt->sv[i].sv == 0) {
			/* SV not valid, skip */
			continue;
		}

		sprintf(output_buffer, "SV: %2d C/N0: %4.1f el: %2d az: %3d signal: %d in fix: %d unhealthy: %d",
			pvt->sv[i].sv,
			pvt->sv[i].cn0 * 0.1,
			pvt->sv[i].elevation,
			pvt->sv[i].azimuth,
			pvt->sv[i].signal,
			(pvt->sv[i].flags & NRF_GNSS_SV_FLAG_USED_IN_FIX) == NRF_GNSS_SV_FLAG_USED_IN_FIX ? 1 : 0,
			(pvt->sv[i].flags & NRF_GNSS_SV_FLAG_UNHEALTHY) == NRF_GNSS_SV_FLAG_UNHEALTHY ? 1 : 0);
		shell_print(gnss_shell_global, "%s", output_buffer);
	}
}

static void print_nmea(nrf_gnss_nmea_data_frame_t *nmea)
{
        if (nmea_output_level == 0) {
                return;
        }

	for (int i = 0; i < NRF_GNSS_NMEA_MAX_LEN; i++) {
		if ((*nmea)[i] == '\r' || (*nmea)[i] == '\n') {
			(*nmea)[i] = '\0';
			break;
		}
	}
	shell_print(gnss_shell_global, "%s", nmea);
}

static void process_gnss_data(nrf_gnss_data_frame_t *gnss_data)
{
	switch (gnss_data->data_id) {
	case NRF_GNSS_PVT_DATA_ID:
		print_pvt(&gnss_data->pvt);
		break;
	case NRF_GNSS_NMEA_DATA_ID:
		print_nmea(&gnss_data->nmea);
		break;
	case NRF_GNSS_AGPS_DATA_ID:
                if (event_output_level > 0) {
                        shell_print(gnss_shell_global, "GNSS: AGPS data needed");
                }
		break;
	}
}

static void gnss_thread(void)
{
	int len;

	k_sem_take(&gnss_sem, K_FOREVER);

	while (true) {
		nrf_gnss_data_frame_t raw_gnss_data = {0};

		while ((len = nrf_recv(fd, &raw_gnss_data,
			               sizeof(nrf_gnss_data_frame_t), 0)) > 0) {
			process_gnss_data(&raw_gnss_data);
		}

		k_sleep(K_MSEC(500));
	}
}

K_THREAD_DEFINE(gnss_socket_thread, GNSS_THREAD_STACK_SIZE,
                gnss_thread, NULL, NULL, NULL,
                GNSS_THREAD_PRIORITY, 0, 0);

static void gnss_init(void)
{
	if (fd > -1) {
		return;
	}

	fd = nrf_socket(NRF_AF_LOCAL, NRF_SOCK_DGRAM, NRF_PROTO_GNSS);
}

int gnss_start(void)
{
	int ret;
	nrf_gnss_delete_mask_t delete_mask;

	gnss_init();

	delete_mask = 0x0;
	ret = nrf_setsockopt(fd,
			     NRF_SOL_GNSS,
			     NRF_SO_GNSS_START,
			     &delete_mask,
			     sizeof(delete_mask));
	if (ret == 0) {
                if (event_output_level > 0) {
                        shell_print(gnss_shell_global, "GNSS: Search started");
                }
	} else {
		shell_error(gnss_shell_global, "GNSS: Failed to start GPS");
	}

	k_sem_give(&gnss_sem);

	return ret;
}

int gnss_stop(void)
{
	int ret;
	nrf_gnss_delete_mask_t delete_mask;

	gnss_init();

	delete_mask = 0x0;
	ret = nrf_setsockopt(fd,
			     NRF_SOL_GNSS,
			     NRF_SO_GNSS_STOP,
			     &delete_mask,
			     sizeof(delete_mask));
	if (ret == 0) {
                if (event_output_level > 0) {
                        shell_print(gnss_shell_global, "GNSS: Search stopped");
                }
        } else {
		shell_error(gnss_shell_global, "GNSS: Failed to stop GPS");
	}

	return ret;
}

int gnss_set_continuous_mode()
{
	/* TODO */

	return 0;
}

int gnss_set_single_fix_mode(uint16_t fix_retry)
{
	/* TODO */

	return 0;
}

int gnss_set_periodic_fix_mode(uint16_t fix_interval, uint16_t fix_retry)
{
	/* TODO */

	return 0;
}

int gnss_set_duty_cycling_policy(enum gnss_duty_cycling_policy policy)
{
	/* TODO */

	return 0;
}

void gnss_set_delete_stored_data(bool value)
{
	/* TODO */
}

int gnss_set_pvt_output_level(uint8_t level)
{
	if (level < 0 || level > 2) {
		return -EINVAL;
	}

	pvt_output_level = level;

	return 0;
}

int gnss_set_nmea_output_level(uint8_t level)
{
	if (level < 0 || level > 1) {
		return -EINVAL;
	}

	nmea_output_level = level;

	return 0;
}

int gnss_set_event_output_level(uint8_t level)
{
	if (level < 0 || level > 1) {
		return -EINVAL;
	}

	event_output_level = level;

	return 0;
}

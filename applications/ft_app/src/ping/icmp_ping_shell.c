#include <stdlib.h>

#include <shell/shell.h>

#include "icmp_ping.h"
#include "icmp_ping_shell.h"

#define PING_USAGE_STR                                                         \
	"USAGE: ping <target_name> <payload_length> <timeout_in_msecs>[ <count>[ <interval_in_msecs>]]"

int icmp_ping_shell(const struct shell *shell, size_t argc, char **argv)
{
	if (argc < 4 || argc > 6) {
		shell_error(shell, "wrong amount of arguments\n");
		shell_print(shell, "%s\n", PING_USAGE_STR);
		return -1;
	}
	
#ifdef NOT_IN_FTA
	shell_print(shell, "argc = %d", argc);
	for (size_t cnt = 0; cnt < argc; cnt++) {
		shell_print(shell, "  argv[%d] = %s", cnt, argv[cnt]);
	}
#endif

	//USAGE: ping <target_name> <payload_length> <timeout_in_msecs>[ <count>[ <interval_in_msecs>]]
	if (argc > 1) {
		char *target_name = argv[1];
		int length = 0;
		int timeout = ICMP_PARAM_TIMEOUT_DEFAULT;
		int count = ICMP_PARAM_COUNT_DEFAULT;
		int interval = ICMP_PARAM_INTERVAL_DEFAULT;

		//TODO: use getopt()

		if (strlen(target_name) > ICMP_MAX_URL) {
			shell_error(shell, "too long target_name");
			return -1;
		}

		length = atoi(argv[2]);
		if (length == 0) {
			shell_warn(
				shell,
				"length not an integer (> 0), defaulting to zero length payload");
		}
		if (length > ICMP_MAX_LEN) {
			shell_error(shell, "Payload size exceeds the limit %d",
				    ICMP_MAX_LEN);
			return -1;
		}

		timeout = atoi(argv[3]);
		if (timeout == 0) {
			shell_warn(
				shell,
				"timeout not an integer (> 0), defaulting to %d msecs",
				ICMP_PARAM_TIMEOUT_DEFAULT);
		}
		if (argc > 4) {
			/* Optional arguments: */
			count = atoi(argv[4]);
			if (count == 0) {
				shell_warn(
					shell,
					"count not an integer (> 0), defaulting to %d",
					ICMP_PARAM_COUNT_DEFAULT);
				count = ICMP_PARAM_COUNT_DEFAULT;
			}
			if (argc == 6) {
				interval = atoi(argv[5]);
				if (interval == 0) {
					shell_warn(
						shell,
						"interval not an integer (> 0), defaulting to %d",
						ICMP_PARAM_INTERVAL_DEFAULT);
					interval = ICMP_PARAM_INTERVAL_DEFAULT;
				}
			}
		}
		icmp_ping_start(shell, target_name, length, timeout, count,
				interval);
	}
	return 0;
}

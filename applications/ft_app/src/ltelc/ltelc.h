#ifndef LTE_CONNECTION_H
#define LTE_CONNECTION_H
#include <modem/lte_lc.h>

#define LTELC_APN_STR_MAX_LENGTH 100
#define LTELC_MAX_PDN_SOCKETS 5 //TODO: what is the actual max in modem?

void ltelc_init(void);
void ltelc_ind_handler(const struct lte_lc_evt *const evt);
int ltelc_pdn_init_and_connect(const char *apn_name);
int ltelc_pdn_disconnect(const char* apn);

#endif

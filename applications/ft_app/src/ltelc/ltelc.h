#ifndef LTE_CONNECTION_H
#define LTE_CONNECTION_H

void ltelc_init(void);
void ltelc_ind_handler(const struct lte_lc_evt *const evt);

#endif

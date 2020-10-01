#ifndef LTE_CONNECTION_H
#define LTE_CONNECTION_H

void lte_conn_init(void);
void lte_conn_ind_handler(const struct lte_lc_evt *const evt);
int lte_conn_shell(const struct shell *shell, size_t argc, char **argv);

#endif

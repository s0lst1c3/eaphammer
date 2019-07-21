#ifndef __EAPHAMMER_EH_SSID_TABLE_T__
#define __EAPHAMMER_EH_SSID_TABLE_T__

#include "uthash/uthash.h"
#include "eh_ssid_t.h"

typedef eh_ssid_t eh_ssid_table_t;

eh_ssid_table_t *eh_ssid_table_t_create(void);
eh_ssid_t *eh_ssid_table_t_find(eh_ssid_table_t *ssid_table, const char *ssid_str);
void eh_ssid_table_t_add(eh_ssid_table_t **ssid_table, eh_ssid_t *next_ssid);
int eh_ssid_table_t_load_file(eh_ssid_table_t **ssid_table, const char *input_file);

#endif

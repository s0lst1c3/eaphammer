#ifndef __EAPHAMMER_EH_STA_TABLE_T__
#define __EAPHAMMER_EH_STA_TABLE_T__

#include "uthash/uthash.h"
#include "eh_sta_t.h"
#include "eh_ssid_table_t.h"

typedef eh_sta_t eh_sta_table_t;

//eh_ssid_table_t *eh_ssid_table_t_create(void);
eh_sta_t *eh_sta_table_t_find(eh_sta_table_t *sta_table, const u8 mac_addr[]);
void eh_sta_table_t_add(eh_sta_table_t **sta_table, eh_sta_t *next_sta);
eh_sta_t* eh_sta_table_t_findsert(eh_sta_table_t **sta_table, const u8 mac_addr[]);
eh_ssid_table_t *eh_sta_table_t_get_ssids(eh_sta_table_t *sta_table, const u8 mac_addr[]);

#endif

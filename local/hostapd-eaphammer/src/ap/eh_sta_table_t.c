#include "utils/includes.h"
#include "utils/common.h"
#include "eh_sta_table_t.h"

eh_sta_t *eh_sta_table_t_find(eh_sta_table_t *sta_table, const u8 mac_addr[]) {

	eh_sta_t *next_sta = NULL;

	HASH_FIND(hh, sta_table, mac_addr, ETH_ALEN, next_sta);

	return next_sta;
}
void eh_sta_table_t_add(eh_sta_table_t **sta_table, eh_sta_t *next_sta) {
	
	HASH_ADD(hh, *sta_table, mac_addr, ETH_ALEN, next_sta);
}

eh_ssid_table_t *eh_sta_table_t_get_ssids(eh_sta_table_t *sta_table, const u8 mac_addr[]) {

	eh_sta_t *next_sta = NULL;

	next_sta = eh_sta_table_t_find(sta_table, mac_addr);
	if (next_sta == NULL) {

		return NULL;
	}
	return next_sta->ssids;
}

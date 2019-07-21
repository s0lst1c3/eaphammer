#include "utils/includes.h"
#include "utils/common.h"
#include "eh_sta_t.h"

eh_sta_t *eh_sta_t_create(const u8 mac_addr[]) {

	eh_sta_t *next_sta = os_malloc(sizeof(eh_sta_t));

	os_memcpy(next_sta->mac_addr, mac_addr, ETH_ALEN);
	next_sta->ssids = NULL;

	return next_sta;
}

eh_ssid_t *eh_sta_t_get_ssid(eh_sta_t *my_sta, const char *ssid_str) {

	eh_ssid_t *next_ssid = NULL;

	HASH_FIND_STR(my_sta->ssids, ssid_str, next_ssid);

	return next_ssid;
}

void eh_sta_t_add_ssid(eh_ssid_t **my_ssids, eh_ssid_t *next_ssid) {

	HASH_ADD_STR(*my_ssids, str, next_ssid);
}

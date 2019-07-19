//#include "../../../uthash/include/uthash.h"
#ifndef __EAPHAMMER_EH_STA_T__
#define __EAPHAMMER_EH_STA_T__

#include "uthash/uthash.h"
#include "eh_ssid_t.h"


struct eh_sta_t {

	u8 mac_addr[6];
	char *mac_str;
	eh_ssid_t *ssids;
	UT_hash_handle hh;
};
typedef struct eh_sta_t eh_sta_t;

eh_sta_t *eh_sta_t_create(const u8 mac_addr[]);

eh_ssid_t *eh_sta_t_get_ssid(eh_sta_t *my_sta, const char *ssid_str);

void eh_sta_t_add_ssid(eh_ssid_t **my_ssids, eh_ssid_t *next_ssid);

#endif

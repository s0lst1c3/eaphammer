#include "uthash/uthash.h"


#ifndef __EAPHAMMER_EH_SSID_T__
#define __EAPHAMMER_EH_SSID_T__

struct eh_ssid_t {

	char str[SSID_MAX_LEN+1];
	u8 bytes[SSID_MAX_LEN];

	size_t len;
	UT_hash_handle hh;
};

typedef struct eh_ssid_t eh_ssid_t;

eh_ssid_t *eh_ssid_t_create(const char *str, const u8 bytes[], const size_t len);

#endif

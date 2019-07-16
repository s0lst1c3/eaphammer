#include "utils/includes.h"
#include "utils/common.h"
#include "eh_ssid_t.h"

eh_ssid_t *eh_ssid_t_create(const char *str, const u8 bytes[], const size_t len) {

	eh_ssid_t *next_ssid = os_malloc(sizeof(eh_ssid_t));

	os_memcpy(next_ssid->str, str, len+1);
	os_memcpy(next_ssid->bytes, bytes, len);
	next_ssid->len = len;

	return next_ssid;
}

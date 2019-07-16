#include "utils/includes.h"
#include "utils/common.h"
#include "eh_ssid_table_t.h"

eh_ssid_table_t *eh_ssid_table_t_create(void) {
	return NULL;
}

eh_ssid_t *eh_ssid_table_t_find(eh_ssid_table_t *ssid_table, const char *ssid_str) {

	eh_ssid_t *next_ssid = NULL;

	HASH_FIND_STR(ssid_table, ssid_str, next_ssid);

	return next_ssid;
}

void eh_ssid_table_t_add(eh_ssid_table_t *ssid_table, eh_ssid_t *next_ssid) {

	HASH_ADD_STR(ssid_table, str, next_ssid);

}

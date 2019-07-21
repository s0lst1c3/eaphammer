#include "utils/includes.h"
#include "utils/common.h"
#include "eh_ssid_iter_t.h"

eh_ssid_iter_t *eh_ssid_iter_t_create(eh_ssid_table_t *ssid_table) {

	eh_ssid_iter_t *iterator;

	iterator = (eh_ssid_iter_t*)ssid_table;

	return iterator;
}

eh_ssid_t *eh_ssid_iter_t_next(eh_ssid_iter_t **iterator) {

	eh_ssid_iter_t *prev = *iterator;

	*iterator = (eh_ssid_iter_t*)(prev->hh.next);

	return prev;
}


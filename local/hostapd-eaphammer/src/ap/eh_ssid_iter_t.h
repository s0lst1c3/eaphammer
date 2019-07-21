#ifndef __EAPHAMMER_EH_SSID_ITER_T__
#define __EAPHAMMER_EH_SSID_ITER_T__

#include "uthash/uthash.h"
#include "eh_ssid_t.h"
#include "eh_ssid_table_t.h"

typedef eh_ssid_t eh_ssid_iter_t;

eh_ssid_iter_t *eh_ssid_iter_t_create(eh_ssid_table_t *ssid_table);
eh_ssid_t *eh_ssid_iter_t_next(eh_ssid_iter_t **iterator);

#endif

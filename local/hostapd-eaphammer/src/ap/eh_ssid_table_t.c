#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void eh_ssid_table_t_add(eh_ssid_table_t **ssid_table, eh_ssid_t *next_ssid) {

	HASH_ADD_STR(*ssid_table, str, next_ssid);

	if (ssid_table == NULL) {

		wpa_printf(MSG_DEBUG, "[EAPHAMMER] simply mindblowing");
	}

}

int eh_ssid_table_t_load_file(eh_ssid_table_t **ssid_table, const char *input_file) {

	FILE *input_handle;
	char *line = NULL;
	size_t buffer_len = 0;
	ssize_t line_len = 0;
	eh_ssid_t *next_ssid = NULL;

	// set up
	input_handle = fopen(input_file, "r");
	if (input_handle == NULL) {
		wpa_printf(MSG_DEBUG, "[EAPHAMMER] Could not open known SSID file for writing: %s", input_file);
		exit(1);
	}

	// do work
    while ((line_len = getline(&line, &buffer_len, input_handle)) != -1) {

		wpa_printf(MSG_DEBUG, "[EAPHAMMER] eh test 3");

		// remove trailing newline character
		line[strcspn(line, "\n")] = '\0';

		next_ssid = eh_ssid_t_create(line, (u8 *)line, line_len-1);
		wpa_printf(MSG_DEBUG, "[EAPHAMMER] Read SSID from file: %s (length: %zu)", next_ssid->str, next_ssid->len);
		wpa_printf(MSG_DEBUG, "[EAPHAMMER] wpa_ssid_txt() output is %s", wpa_ssid_txt(next_ssid->bytes, next_ssid->len));

		HASH_ADD_STR(*ssid_table, str, next_ssid);
    }

	if (ssid_table == NULL) {


		wpa_printf(MSG_DEBUG, "[EAPHAMMER] no fucking idea");
	}

	// tear down
	fclose(input_handle);
	if (line) {

		free(line);
	}

	return 0;
}

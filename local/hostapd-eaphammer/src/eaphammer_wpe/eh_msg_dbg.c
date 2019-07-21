#include "utils/includes.h"
#include "utils/common.h"
#include "eh_msg_dbg.h"

void eh_msg_dbg_bc_probe_rec(const u8 mac_addr[]) {

	wpa_printf(MSG_DEBUG, 
		"[EAPHAMMER] PROBE RECEIVED (broadcast): " MACSTR " looking for ANY",
		MAC2STR(mac_addr));
}

void eh_msg_dbg_add_ssid_from_sta(const u8 *ssid, size_t ssid_len, const u8 sta[]) {

	wpa_printf(MSG_DEBUG,
			"[EAPHAMMER] LOGGING PROBE (directed): " MACSTR " looking for %s(%zu)",
			MAC2STR(sta),
			wpa_ssid_txt(ssid, ssid_len),
			ssid_len);
}
void eh_msg_dbg_d_probe(const u8 *ssid, size_t ssid_len, const u8 sta[]) {

	wpa_printf(MSG_INFO,
		"[EAPHAMMER] PROBE RECEIVED (directed): " MACSTR " looking for %s",
			MAC2STR(sta),
			wpa_ssid_txt(ssid, ssid_len));
}

void eh_msg_dbg_gen_probe_resp(const u8 *ssid, size_t ssid_len, const u8 sta[]) {
	
	wpa_printf(MSG_DEBUG,
			"[EAPHAMMER] GENERATING RESPONSE: %.*s (%zu) for " MACSTR,
			ssid_len,
			ssid,
			ssid_len,
			MAC2STR(sta));
}

void eh_msg_dbg_gen_bc_probe_resp(char *ssid, size_t ssid_len, const u8 sta[]) {
	
	wpa_printf(MSG_DEBUG,
			"[EAPHAMMER] GENERATING RESPONSE (broadcast): %s (%zu) for " MACSTR,
			ssid,
			ssid_len,
			MAC2STR(sta));
}

void eh_msg_dbg_exc_probe_req_rec(const u8 sta[], const char *ssid) {

	wpa_printf(MSG_EXCESSIVE,
			"[EAPHAMMER] PROBE RECEIVED (directed): " MACSTR " looking for %s",
			MAC2STR(sta),
			ssid); 

}

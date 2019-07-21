#ifndef __EAPHAMMER_EH_MSG_DBG__
#define __EAPHAMMER_EH_MSG_DBG__

void eh_msg_dbg_bc_probe_rec(const u8 mac_addr[]);
void eh_msg_dbg_add_ssid_from_sta(const u8 *ssid, size_t ssid_len, const u8 sta[]);
void eh_msg_dbg_d_probe(const u8 *ssid, size_t ssid_len, const u8 sta[]);
void eh_msg_dbg_gen_probe_resp(const u8 *ssid, size_t ssid_len, const u8 sta[]);
void eh_msg_dbg_gen_bc_probe_resp(char *ssid, size_t ssid_len, const u8 sta[]);
void eh_msg_dbg_exc_probe_req_rec(const u8 sta[], const char *ssid);

#endif

/*
    wpe.h - 
        brad.antoniewicz@foundstone.com
        Implements WPE (Wireless Pwnage Edition) functionality within 
        hostapd.

        WPE functionality focuses on targeting connecting users. At 
        it's core it implements credential logging (originally 
        implemented in FreeRADIUS-WPE), but also includes other patches
        for other client attacks.

            FreeRADIUS-WPE: https://github.com/brad-anton/freeradius-wpe
*/
#include <openssl/ssl.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ap/eh_ssid_table_t.h"
#include "ap/eh_sta_table_t.h"

struct eaphammer_global_config {
    char *logfile;
    FILE *logfile_fp;
	char *autocrack_fifo; // eaphammer
	FILE *autocrack_fifo_fp; // eaphammer
	unsigned int use_autocrack; // eaphammer
	u8 acl_has_wildcards; // eaphammer
	u8 use_ssid_acl;
	u8 ssid_acl_mode;
    unsigned int always_return_success;
    char *known_ssids_file;
    char *psk_capture_file;
	u8 capture_wpa_handshakes;
	u8 use_karma;
	u8 known_beacons;
	u8 singed_pants;
	eh_ssid_table_t *ssid_table;
	eh_sta_table_t *sta_table;
};

extern struct eaphammer_global_config eaphammer_global_conf;

#define n2s(c,s)((s=(((unsigned int)(c[0]))<< 8)| \
       (((unsigned int)(c[1]))    )),c+=2)

#define s2n(s,c) ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
        c[1]=(unsigned char)(((s)    )&0xff)),c+=2)


void wpe_log_file_and_stdout(char const *fmt, ...);
void eaphammer_write_fifo(const u8 *username, size_t username_len, // eaphammer 
			const u8 *challenge, size_t challenge_len, const u8 *response, size_t response_len); // eaphammer
void wpe_log_chalresp(char *type, const u8 *full_username, size_t full_username_len, const u8 *username, size_t username_len, const u8 *challenge, size_t challenge_len, const u8 *response, size_t response_len, const u8 eap_id);
void wpe_log_basic(char *type, const u8 *username, size_t username_len, const u8 *password, size_t password_len);

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

struct wpe_config {
    char *wpe_logfile;
    FILE *wpe_logfile_fp;
    unsigned int wpe_enable_return_success;
};

extern struct wpe_config wpe_conf;

#define n2s(c,s)((s=(((unsigned int)(c[0]))<< 8)| \
       (((unsigned int)(c[1]))    )),c+=2)

#define s2n(s,c) ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
        c[1]=(unsigned char)(((s)    )&0xff)),c+=2)


void wpe_log_file_and_stdout(char const *fmt, ...);
void wpe_log_chalresp(char *type, const u8 *username, size_t username_len, const u8 *challenge, size_t challenge_len, const u8 *response, size_t response_len);
void wpe_log_basic(char *type, const u8 *username, size_t username_len, const u8 *password, size_t password_len);

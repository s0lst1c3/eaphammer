#ifndef WIRELESS_LITE_H
#define WIRELESS_LITE_H

/* cleaned up from linux/wireless.h */

#include <net/if.h>

#define SIOCSIWFREQ 0x8B04
#define SIOCSIWMODE 0x8B06
#define SIOCGIWMODE 0x8B07
#define SIOCGIWNAME 0x8B01

#define IW_FREQ_FIXED 0x01

#define IW_MODE_AUTO 0
#define IW_MODE_ADHOC 1
#define IW_MODE_INFRA 2
#define IW_MODE_MASTER 3
#define IW_MODE_REPEAT 4
#define IW_MODE_SECOND 5
#define IW_MODE_MONITOR 6
#define IW_MODE_MESH 7

struct iw_quality {
	unsigned char qual;
	unsigned char level;
	unsigned char noise;
	unsigned char updated;
};

struct iw_param {
	int value;
	unsigned char fixed;
	unsigned char disabled;
	unsigned short flags;
};

struct iw_point {
	void *pointer;
	unsigned short length;
	unsigned short flags;
};

struct iw_freq {
	int m;
	short e;
	unsigned char i;
	unsigned char flags;
};

union iwreq_data {
	char name[IFNAMSIZ];
	struct iw_point	essid;
	struct iw_param	nwid;
	struct iw_freq	freq;
	struct iw_param	sens;
	struct iw_param	bitrate;
	struct iw_param	txpower;
	struct iw_param	rts;
	struct iw_param	frag;
	unsigned mode;
	struct iw_param	retry;
	struct iw_point	encoding;
	struct iw_param	power;
	struct iw_quality qual;
	struct sockaddr	ap_addr;
	struct sockaddr	addr;
	struct iw_param	param;
	struct iw_point	data;
};

struct	iwreq {
	union {
		char ifrn_name[IFNAMSIZ];
	} ifr_ifrn;
	union iwreq_data u;
};

#endif


/* Copyright 2006 Aruba Networks */

#ifndef IEEE8021X_H
#define IEEE8021X_H

/* The 802.1x header indicates a version, type and length */
struct ieee8021x {
	uint8_t    version;
	uint8_t    type;
	uint16_t   len;
} __attribute__ ((packed));
#define DOT1XHDR_LEN sizeof(struct ieee8021x)

#define DOT1X_VERSION 1
#define DOT1X_TYPE_EAP 0

#endif

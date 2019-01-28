/* Copyright 2006 Aruba Networks */

#ifndef IEEE80211_H
#define IEEE80211_H

#define DOT11HDR_A1_LEN 10
#define DOT11HDR_A3_LEN 24
#define DOT11HDR_A4_LEN 30
#define DOT11HDR_MAC_LEN 6
#define DOT11HDR_MINLEN DOT11HDR_A1_LEN

#define DOT11_FC_TYPE_MGMT 0
#define DOT11_FC_TYPE_CTRL 1
#define DOT11_FC_TYPE_DATA 2

#define DOT11_FC_SUBTYPE_ASSOCREQ    0
#define DOT11_FC_SUBTYPE_ASSOCRESP   1
#define DOT11_FC_SUBTYPE_REASSOCREQ  2
#define DOT11_FC_SUBTYPE_REASSOCRESP 3
#define DOT11_FC_SUBTYPE_PROBEREQ    4
#define DOT11_FC_SUBTYPE_PROBERESP   5
#define DOT11_FC_SUBTYPE_BEACON      8
#define DOT11_FC_SUBTYPE_ATIM        9
#define DOT11_FC_SUBTYPE_DISASSOC    10
#define DOT11_FC_SUBTYPE_AUTH        11
#define DOT11_FC_SUBTYPE_DEAUTH      12

#define DOT11_FC_SUBTYPE_PSPOLL      10
#define DOT11_FC_SUBTYPE_RTS         11
#define DOT11_FC_SUBTYPE_CTS         12
#define DOT11_FC_SUBTYPE_ACK         13
#define DOT11_FC_SUBTYPE_CFEND       14
#define DOT11_FC_SUBTYPE_CFENDACK    15

#define DOT11_FC_SUBTYPE_DATA            0
#define DOT11_FC_SUBTYPE_DATACFACK       1
#define DOT11_FC_SUBTYPE_DATACFPOLL      2
#define DOT11_FC_SUBTYPE_DATACFACKPOLL   3
#define DOT11_FC_SUBTYPE_DATANULL        4
#define DOT11_FC_SUBTYPE_CFACK           5
#define DOT11_FC_SUBTYPE_CFACKPOLL       6
#define DOT11_FC_SUBTYPE_CFACKPOLLNODATA 7
#define DOT11_FC_SUBTYPE_QOSDATA         8
/* 9 - 11 reserved as of 11/7/2005 - JWRIGHT */
#define DOT11_FC_SUBTYPE_QOSNULL         12

/* Fixed parameter length values for mgmt frames */
#define DOT11_MGMT_BEACON_FIXEDLEN 12
#define DOT11_MGMT_ASSOCREQ_FIXEDLEN 4
#define DOT11_MGMT_ASSOCRESP_FIXEDLEN 6
#define DOT11_MGMT_AUTH_FIXEDLEN 6

/* Authentication algorithm values */
#define DOT11_MGMT_AUTHALGO_SHARED 1
#define DOT11_MGMT_AUTHALGO_OPEN 0

/* Information element identifiers */
#define DOT11_IE_SSIDSET 0
#define DOT11_IE_DSPARAMSET 3
#define DOT11_IE_RSN 48
#define DOT11_IE_WPA 221

/* IE Cipher suite mechanisms for RSN/WPA */
#define DOT11_RSN_CIPHER_GROUP	0	/* Use the group cipher for unicast */
#define DOT11_RSN_CIPHER_WEP40	1	/* WEP-40 */
#define DOT11_RSN_CIPHER_TKIP	2	/* TKIP */
#define DOT11_RSN_CIPHER_RSVD	3	/* Reserved */
#define DOT11_RSN_CIPHER_CCMP	4	/* CCMP */
#define DOT11_RSN_CIPHER_WEP104	5	/* WEP-104 */

/* IE Authentication suite mechanksms for RSN/WPA */
#define DOT11_RSN_AUTH_PMKDER	1	/* Key derived from PMK via 802.1x or
					   key caching mechanism. */
#define DOT11_RSN_AUTH_PSK	2	/* Key derived from PSK */

/* RSN/WPA element constants */
#define DOT11_RSN_IE_VERSION	1
#define DOT11_RSN_OUI		"\x00\x0f\xac"
#define DOT11_RSN_OUI_LEN	3
#define DOT11_WPA_IE_VERSION	1
#define DOT11_WPA_TAG		"\x00\x50\xf2\x01"
#define DOT11_WPA_TAG_LEN	4
#define DOT11_WPA_OUI		"\x00\x50\xf2"
#define DOT11_WPA_OUI_LEN	3


/* Authentication identifiers */
#define DOT11_PREVAUTH_INVALID 2

struct dot11hdr {
	union {
		struct {
			uint8_t		version:2;
			uint8_t		type:2;
			uint8_t		subtype:4;
			uint8_t		to_ds:1;
			uint8_t		from_ds:1;
			uint8_t		more_frag:1;
			uint8_t		retry:1;
			uint8_t		pwrmgmt:1;
			uint8_t		more_data:1;
			uint8_t		protected:1;
			uint8_t		order:1;
		} __attribute__ ((packed)) fc;

		uint16_t	fchdr;
	} u1;

	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];

	union {
		struct {
			uint16_t	fragment:4;
			uint16_t	sequence:12;
		} __attribute__ ((packed)) seq;

		uint16_t	seqhdr;
	} u2;

} __attribute__ ((packed));

#define dot11hdra3 dot11hdr
#define ieee80211 dot11hdr

struct dot11hdr_a1 {
	union {
		struct {
			uint8_t		version:2;
			uint8_t		type:2;
			uint8_t		subtype:4;
			uint8_t		to_ds:1;
			uint8_t		from_ds:1;
			uint8_t		more_frag:1;
			uint8_t		retry:1;
			uint8_t		pwrmgmt:1;
			uint8_t		more_data:1;
			uint8_t		protected:1;
			uint8_t		order:1;
		} __attribute__ ((packed)) fc;

		uint16_t	fchdr;
	} u1;

	uint16_t	duration;
	uint8_t		addr1[6];
} __attribute__ ((packed));

struct dot11hdr_a4 {
	union {
		struct {
			uint8_t		version:2;
			uint8_t		type:2;
			uint8_t		subtype:4;
			uint8_t		to_ds:1;
			uint8_t		from_ds:1;
			uint8_t		more_frag:1;
			uint8_t		retry:1;
			uint8_t		pwrmgmt:1;
			uint8_t		more_data:1;
			uint8_t		protected:1;
			uint8_t		order:1;
		} __attribute__ ((packed)) fc;

		uint16_t	fchdr;
	} u1;

	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];

	union {
		struct {
			uint16_t	fragment:4;
			uint16_t	sequence:12;
		} __attribute__ ((packed)) seq;

		uint16_t	seqhdr;
	} u2;

	uint8_t		addr4[6];

} __attribute__ ((packed));

struct dot11_mgmt {
	union {
		struct {
			uint16_t auth_algo;
			uint16_t auth_transaction;
			uint16_t status_code;
			/* possibly followed by Challenge text */
			uint8_t variable[0];
		} __attribute__ ((packed)) auth;
		struct {
			uint16_t reason_code;
		} __attribute__ ((packed)) deauth;
		struct {
			uint16_t capab_info;
			uint16_t listen_interval;
			/* followed by SSID and Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) assoc_req;
		struct {
			uint16_t capab_info;
			uint16_t status_code;
			uint16_t aid;
			/* followed by Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) assoc_resp, reassoc_resp;
		struct {
			uint16_t capab_info;
			uint16_t listen_interval;
			uint8_t current_ap[6];
			/* followed by SSID and Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) reassoc_req;
		struct {
			uint16_t reason_code;
		} __attribute__ ((packed)) disassoc;
		struct {
			uint8_t variable[0];
		} __attribute__ ((packed)) probe_req;
		struct {
			uint8_t timestamp[8];
			uint16_t beacon_int;
			uint16_t capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			uint8_t variable[0];
		} __attribute__ ((packed)) beacon;
	} u;
} __attribute__ ((packed));

/* IEEE 802.11 fixed parameters */
struct ieee80211_beacon_fixparm {
	uint8_t timestamp[8];
	uint16_t beaconinterval;
	uint16_t capability;
} __attribute__ ((packed));

struct ieee80211_qos {
	uint8_t priority:3;
	uint8_t reserved3:1;
	uint8_t eosp:1;
	uint8_t ackpol:2;
	uint8_t reserved1:1;
	uint8_t reserved2;
} __attribute__ ((packed));
#define DOT11HDR_QOS_LEN 2

struct ieee80211_wep {
	uint8_t iv[3];

	union {
		uint8_t indexhdr;

		struct {
			uint8_t reserved:6;
			uint8_t keyid:2;
		} __attribute__ ((packed)) index;
	} u1;
} __attribute__ ((packed));

struct ieee80211_tkip {
	union {
		struct {
			uint8_t tsc1;
			uint8_t wepseed;
			uint8_t tsc0;
			uint8_t reserved1:5;
			uint8_t extiv:1;
			uint8_t keyid:2;
		} __attribute__ ((packed)) iv;

		uint8_t ivhdr;
	} u1;

	union {
		struct {
			uint8_t tsc2;
			uint8_t tsc3;
			uint8_t tsc4;
			uint8_t tsc5;
		} extiv;

		uint8_t extivhdr;
	} u2;

} __attribute__ ((packed));

struct ieee80211_ccmp {
	union {
		struct {
			uint8_t pn0;
			uint8_t pn1;
			uint8_t reserved1;
			uint8_t reserved2:5;
			uint8_t extiv:1;
			uint8_t keyid:2;
		} __attribute__ ((packed)) iv;

		uint8_t ivhdr;
	} u1;

	union {
		struct {
			uint8_t pn2;
			uint8_t pn3;
			uint8_t pn4;
			uint8_t pn5;
		} extiv;

		uint8_t extivhdr[4];
	} u2;

} __attribute__ ((packed));

struct ieee8022 {
	uint8_t    dsap;
	uint8_t    ssap;
	uint8_t    control;
	uint8_t    oui[3];
	uint16_t   type;
} __attribute__ ((packed));
#define DOT2HDR_LEN sizeof(struct ieee8022)

#define IEEE8022_SNAP 0xaa
#define IEEE8022_TYPE_IP 0x0800
#define IEEE8022_TYPE_DOT1X 0x888e
#define IEEE8022_TYPE_ARP 0x0806


#endif

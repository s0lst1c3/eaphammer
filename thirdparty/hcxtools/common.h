#include <stdbool.h>
#include <stddef.h>

#ifdef __APPLE__
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif

#define NEWENTY -1

#define HCCAPX_SIGNATURE 0x58504348
#define HCCAPX_VERSION 4


enum ieee80211_radiotap_presence {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	/* 18 is XChannel, but it's not defined yet */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};


#define	MAC_SIZE_ACK	(10)
#define	MAC_SIZE_RTS	(16)
#define	MAC_SIZE_NORM	(24)
#define	MAC_SIZE_QOS	(26)
#define	MAC_SIZE_LONG	(30)

#define	MAC_TYPE_MGMT	0x0
#define	MAC_TYPE_CTRL	0x1
#define	MAC_TYPE_DATA	0x2
#define	MAC_TYPE_RSVD	0x3

// management subtypes
#define	MAC_ST_ASSOC_REQ	0x0
#define	MAC_ST_ASSOC_RESP	0x1
#define	MAC_ST_REASSOC_REQ	0x2
#define	MAC_ST_REASSOC_RESP	0x3
#define	MAC_ST_PROBE_REQ	0x4
#define	MAC_ST_PROBE_RESP	0x5
#define	MAC_ST_BEACON		0x8
#define	MAC_ST_DISASSOC		0xA
#define	MAC_ST_AUTH		0xB
#define	MAC_ST_AUTH_REQ		0x1
#define	MAC_ST_AUTH_RESP	0x2
#define	MAC_ST_DEAUTH		0xC
#define	MAC_ST_ACTION		0xD
// data subtypes
#define	MAC_ST_DATA		0x0
#define	MAC_ST_NULL		0x4
#define	MAC_ST_QOSDATA		0x8
#define	MAC_ST_QOSNULL		0xC
// control subtypes
#define	MAC_ST_BACK_REQ		0x8
#define	MAC_ST_BACK		0x9
#define	MAC_ST_PSP		0xA
#define	MAC_ST_RTS		0xB
#define	MAC_ST_CTS		0xC
#define	MAC_ST_ACK		0xD

/* Reason codes (IEEE 802.11-2007, 7.3.1.7, Table 7-22) */
#define WLAN_REASON_UNSPECIFIED 1
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA 6
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA 7
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT 8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9
/* IEEE 802.11h */
#define WLAN_REASON_PWR_CAPABILITY_NOT_VALID 10
#define WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID 11
/* IEEE 802.11i */
#define WLAN_REASON_INVALID_IE 13
#define WLAN_REASON_MICHAEL_MIC_FAILURE 14
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IE_IN_4WAY_DIFFERS 17
#define WLAN_REASON_GROUP_CIPHER_NOT_VALID 18
#define WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID 19
#define WLAN_REASON_AKMP_NOT_VALID 20
#define WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION 21
#define WLAN_REASON_INVALID_RSN_IE_CAPAB 22
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23
#define WLAN_REASON_CIPHER_SUITE_REJECTED 24

#define IEEE80211_SEQ_SEQ_MASK	0xfff0
#define IEEE80211_SEQ_SEQ_SHIFT	4

#define WBIT(n) (1 << (n))
#define WPA_KEY_INFO_TYPE_MASK (WBIT(0) | WBIT(1) | WBIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 WBIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES WBIT(1)
#define WPA_KEY_INFO_KEY_TYPE WBIT(3) /* 1 = Pairwise, 0 = Group key */
#define WPA_KEY_INFO_KEY_INDEX_MASK (WBIT(4) | WBIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL WBIT(6)  /* pairwise */
#define WPA_KEY_INFO_TXRX WBIT(6) /* group */
#define WPA_KEY_INFO_ACK WBIT(7)
#define WPA_KEY_INFO_MIC WBIT(8)
#define WPA_KEY_INFO_SECURE WBIT(9)
#define WPA_KEY_INFO_ERROR WBIT(10)
#define WPA_KEY_INFO_REQUEST WBIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA WBIT(12) /* IEEE 802.11i/RSN only */


struct radiotap_header
{
 uint8_t	it_version;
 uint8_t	it_pad;
 uint16_t	it_len;
 uint32_t	it_present;
} __attribute__((__packed__));
typedef struct radiotap_header rth_t;
#define	RTH_SIZE (sizeof(rth_t))


struct ppi_packet_header
{
 uint8_t  pph_version;
 uint8_t  pph_flags;
 uint16_t pph_len;
 uint32_t pph_dlt;
} __attribute__((packed));
typedef struct ppi_packet_header ppi_packet_header_t;
#define	PPIH_SIZE (sizeof(ppi_packet_header_t))


struct adr_frame
{
 uint8_t	addr[6];
};
typedef struct adr_frame adr_t;
#define	ADR_SIZE (sizeof(adr_t))


struct loopb_header
{
 uint32_t	family;
} __attribute__((packed));
typedef struct loopb_header loopb_header_t;
#define	LOOPB_SIZE (sizeof(loopb_header_t))


struct ether_header
{
 adr_t		addr1;
 adr_t		addr2;
 uint16_t	ether_type;
} __attribute__((packed));
typedef struct ether_header ether_header_t;
#define	ETHER_SIZE (sizeof(ether_header_t))


struct qos_frame
{
 uint8_t	control;
 uint8_t	flags;
};
typedef struct qos_frame qos_t;
#define	QOS_SIZE (sizeof(qos_t))


#if !defined __BYTE_ORDER || (__BIG_ENDIAN == __LITTLE_ENDIAN)
#error Portability fix needed here
#endif
struct mac_frame
{
#if __BYTE_ORDER == __BIG_ENDIAN
 unsigned	subtype : 4;
 unsigned	type : 	2;
 unsigned	version : 2;

 unsigned	ordered : 1;
 unsigned	protected : 1;
 unsigned	more_data : 1;
 unsigned	power : 1;
 unsigned	retry : 1;
 unsigned	more_frag : 1;
 unsigned	from_ds : 1;
 unsigned	to_ds : 1;
#else
 unsigned	version : 2;
 unsigned	type : 	2;
 unsigned	subtype : 4;

 unsigned	to_ds : 1;
 unsigned	from_ds : 1;
 unsigned	more_frag : 1;
 unsigned	retry : 1;
 unsigned	power : 1;
 unsigned	more_data : 1;
 unsigned	protected : 1;
 unsigned	ordered : 1;
#endif
 uint16_t	duration;
 adr_t		addr1;
 adr_t		addr2;
 adr_t		addr3;
 uint16_t	sequence;
 adr_t		addr4;
 qos_t		qos;
};
typedef struct mac_frame mac_t;


struct llc_frame
{
 uint8_t	dsap;
 uint8_t	ssap;
 uint8_t	control;
 uint8_t	org[3];
 uint16_t	type;
#define	LLC_TYPE_AUTH	0x888e
#define	LLC_TYPE_IPV4	0x0800
#define	LLC_TYPE_IPV6	0x86dd
#define	LLC_TYPE_PREAUT	0x88c7
#define	LLC_TYPE_FRRR	0x890d
};
typedef struct llc_frame llc_t;
#define	LLC_SIZE (sizeof(llc_t))
#define LLC_SNAP 0xaa


struct ieee_tag
{
 uint8_t		id;
#define	TAG_SSID	0x00
#define	TAG_RATE	0x01
#define	TAG_CHAN	0x03
#define	TAG_XRAT	0x32
#define	TAG_FBT		0x37
#define TAG_VENDORSPEC	0xdd
 uint8_t		len;
 uint8_t		data[1];
} __attribute__((__packed__));
typedef struct ieee_tag tag_t;
#define	TAGINFO_SIZE offsetof(tag_t, data)


struct beaconinfo
{
 uint64_t beacon_timestamp;
 uint16_t beacon_interval;
 uint16_t beacon_capabilities;
} __attribute__((__packed__));
typedef struct beaconinfo beacon_t;
#define	BEACONINFO_SIZE (sizeof(beacon_t))


struct essidinfo
{
    uint8_t info_essid;
    uint8_t info_essid_len;
    uint8_t *essid[1];
} __attribute__((__packed__));
typedef struct essidinfo essid_t;
#define ESSIDINFO_SIZE offsetof(essid_t, essid)


struct authenticationf
{
 uint16_t authentication_algho;
 uint16_t authentication_seq;
} __attribute__((__packed__));
typedef struct authenticationf authf_t;
#define	AUTHF_SIZE (sizeof(authf_t))


struct associationreqf
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
} __attribute__((__packed__));
typedef struct associationreqf assocreq_t;
#define	ASSOCIATIONREQF_SIZE (sizeof(assocreq_t))


struct associationresf
{
 uint16_t ap_capabilities;
 uint16_t ap_status;
 uint16_t ap_associd;
 } __attribute__((__packed__));
typedef struct associationresf assocres_t;
#define	ASSOCIATIONRESF_SIZE (sizeof(assocres_t))


struct reassociationreqf
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
 adr_t	  addr3;
} __attribute__((__packed__));
typedef struct reassociationreqf reassocreq_t;
#define	REASSOCIATIONREQF_SIZE (sizeof(reassocreq_t))


struct mpdu_frame
{
 uint8_t pn[3];
 uint8_t keyid;
 uint8_t exitiv[4];
};
typedef struct mpdu_frame mpdu_frame_t;
#define	MPDUF_SIZE (sizeof(mpdu_frame_t))


struct eap_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	keytype;
 uint16_t	keyinfo;
 uint16_t	keylen;
 uint64_t	replaycount;
 uint8_t	nonce[32];
 uint8_t	keyiv[16];
 uint64_t	keyrsc;
 uint8_t	keyid[8];
 uint8_t	keymic[16];
 uint16_t	wpadatalen;
 uint8_t	wpadata[10];
} __attribute__((__packed__));
typedef struct eap_frame eap_t;
#define	EAP_SIZE (sizeof(eap_t))


struct vendor_id
{
 uint8_t	vid[3];
};
typedef struct vendor_id vid_t;
#define	VID_SIZE (sizeof(vidt_t))


struct eapext_frame
{
 uint8_t		version;
 uint8_t		type;
 uint16_t		len;
 uint8_t		eapcode;
#define	EAP_CODE_REQ		1
#define	EAP_CODE_RESP		2
#define	EAP_CODE_SUCCESS	3
#define	EAP_CODE_FAILURE	4
#define	EAP_CODE_INITIATE	5
#define	EAP_CODE_FINISH		6
 uint8_t		eapid;
 uint16_t		eaplen;
 uint8_t		eaptype;
#define EAP_TYPE_EAP		0
#define EAP_TYPE_ID		1
#define EAP_TYPE_NOTIFY		2
#define EAP_TYPE_NAK		3
#define EAP_TYPE_MD5		4
#define EAP_TYPE_OTP		5
#define EAP_TYPE_GTC		6
#define EAP_TYPE_RSA		9
#define EAP_TYPE_DSS		10
#define EAP_TYPE_KEA		11
#define EAP_TYPE_KEA_VALIDATE	12
#define EAP_TYPE_TLS		13
#define EAP_TYPE_AXENT		14
#define EAP_TYPE_RSA_SSID	15
#define EAP_TYPE_RSA_ARCOT	16
#define EAP_TYPE_LEAP		17
#define EAP_TYPE_SIM		18
#define EAP_TYPE_SRP_SHA1	19
#define EAP_TYPE_TTLS		21
#define EAP_TYPE_RAS		22
#define EAP_TYPE_AKA		23
#define EAP_TYPE_3COMEAP	24
#define EAP_TYPE_PEAP		25
#define EAP_TYPE_MSEAP		26
#define EAP_TYPE_MAKE		27
#define EAP_TYPE_CRYPTOCARD	28
#define EAP_TYPE_MSCHAPV2	29
#define EAP_TYPE_DYNAMICID	30
#define EAP_TYPE_ROB		31
#define EAP_TYPE_POTP		32
#define EAP_TYPE_MSTLV		33
#define EAP_TYPE_SENTRI		34
#define EAP_TYPE_AW		35
#define EAP_TYPE_CSBA		36
#define EAP_TYPE_AIRFORT	37
#define EAP_TYPE_HTTPD		38
#define EAP_TYPE_SS		39
#define EAP_TYPE_DC		40
#define EAP_TYPE_SPEKE		41
#define EAP_TYPE_MOBAC		42
#define EAP_TYPE_FAST		43
#define EAP_TYPE_ZLXEAP		44
#define EAP_TYPE_LINK		45
#define EAP_TYPE_PAX		46
#define EAP_TYPE_PSK		47
#define EAP_TYPE_SAKE		48
#define EAP_TYPE_IKEV2		49
#define EAP_TYPE_AKA1		50
#define EAP_TYPE_GPSK		51
#define EAP_TYPE_PWD		52
#define EAP_TYPE_EKE1		53
#define EAP_TYPE_PTEAP		54
#define EAP_TYPE_TEAP		55
#define	EAP_TYPE_EXPAND		254
#define EAP_TYPE_EXPERIMENTAL	255
 uint8_t		data[1];
} __attribute__((__packed__));
typedef struct eapext_frame eapext_t;
#define	EAPEXT_SIZE offsetof(eapext_t, data)

struct eapri_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	eapcode;
 uint8_t	eapid;
 uint16_t	eaplen;
 uint8_t	eaptype;
 uint8_t	identity[];
} __attribute__((__packed__));
typedef struct eapri_frame eapri_t;
#define	EAPRI_SIZE (sizeof(eapri_t))


struct eapleap_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	eapcode;
 uint8_t	eapid;
 uint16_t	eaplen;
 uint8_t	eaptype;
 uint8_t	leapversion;
 uint8_t	leapreserved;
 uint8_t	leapcount;
 uint8_t	leapdata[];
} __attribute__((__packed__));
typedef struct eapleap_frame eapleap_t;
#define	EAPLEAP_SIZE (sizeof(eapleap_t))


struct eapmd5_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	eapcode;
 uint8_t	eapid;
 uint16_t	eaplen;
 uint8_t	eaptype;
 uint8_t	eapvaluesize;
 uint8_t	md5data[];
} __attribute__((__packed__));
typedef struct eapmd5_frame eapmd5_t;
#define	EAPMD5_SIZE (sizeof(eapmd5_t))


struct wps_vtag
{
	uint16_t		id;
#define	TAG_WPS_VERSION	"\x10\x4A"
#define	TAG_WPS_STATE	"\x10\x44"
#define	TAG_WPS_APLOCK	"\x10\x57"
	uint16_t		len;
	uint8_t		data[];
#define	TAG_WPS_CONFIG	2
#define	TAG_WPS_LOCKED	1
};
typedef struct wps_vtag vtag_t;
#define	VTAG_SIZE (sizeof(vtag_t))


struct wps_frame
{
	uint8_t		vid[3];
#define	WPS_VENDOR	"\x00\x37\x2a"
	uint32_t	type;
#define	WPS_SIMPLECONF	1
	uint8_t		op;
#define	WSC_OP_NACK	3
#define	WSC_OP_MSG	4
	uint8_t		flags;
	vtag_t		tags[];
#define	WPS_MSG_TYPE	"\x10\x22"
#define	WPS_BEACON		0x01
#define	WPS_PROBEREQUEST	0x02
#define	WPS_PROBERESPONSE	0x03
#define	WPS_MSG_M1		0x04
#define	WPS_MSG_M2		0x05
#define	WPS_MSG_M2D		0x06
#define	WPS_MSG_M3		0x07
#define	WPS_MSG_M4		0x08
#define	WPS_MSG_M5		0x09
#define	WPS_MSG_M6		0x0a
#define	WPS_MSG_M7		0x0b
#define	WPS_MSG_M8		0x0c
#define	WPS_MSG_ACK		0x0d
#define	WPS_MSG_NACK		0x0e
#define	WPS_MSG_DONE		0x0f
} __attribute__((__packed__));
typedef struct wps_frame wps_t;
#define	WPS_SIZE (sizeof(wps_t))


struct ipv4_frame
{
 uint8_t	ver_hlen;
 uint8_t	tos;
 uint16_t	len;
 uint16_t	ipid;
 uint16_t	flags_offset;
 uint8_t	ttl;
 uint8_t	nextprotocol;
 uint16_t	checksum;
 uint8_t	srcaddr[4];
 uint8_t	dstaddr[4];
} __attribute__ ((packed));
typedef struct ipv4_frame ipv4_frame_t;
#define	IPV4_SIZE (sizeof(ipv4_frame_t))
#define	IPV4_SIZE_MIN 20
#define	IPV4_SIZE_MAX 64


struct ipv6_frame
{
 uint32_t	ver_class;
 uint16_t	len;
 uint8_t	nextprotocol;
 uint8_t	hoplimint;
 uint8_t	srcaddr[16];
 uint8_t	dstaddr[16];
} __attribute__ ((packed));
typedef struct ipv6_frame ipv6_frame_t;
#define	IPV6_SIZE (sizeof(ipv6_frame_t))


struct udp_frame
{
 uint16_t	port_source;
 uint16_t	port_destination;
 uint16_t	length;
 uint16_t	checksum;
} __attribute__ ((packed));
typedef struct udp_frame udp_frame_t;
#define	UDP_SIZE (sizeof(udp_frame_t))


#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */
#define NEXTHDR_MAX		255


struct tcp_frame
{
 uint16_t   sourceport;
 uint16_t   destinationport;
 uint32_t   relsequencenumber;
 uint32_t   relacknumber;
 uint8_t    tcphdlen /* x 4 */;
 uint8_t    tcpflags;
} __attribute__ ((packed));
typedef struct tcp_frame tcp_frame_t;


struct tacacsp_frame
{
 uint8_t   version;
#define TACACSP_VERSION 0xc0
 uint8_t   type;
#define TACACS_AUTHENTICATION 1
 uint8_t   sequencenumber;
 uint8_t   flags;
 uint32_t  sessionid;
 uint32_t  datalen;
 uint8_t   data[1];
} __attribute__ ((packed));
typedef struct tacacsp_frame tacacsp_frame_t;
#define	TACACSP_SIZE offsetof(tacacsp_frame_t, data)


struct gre_frame
{
 uint16_t   flags;
 uint16_t   type;
 uint16_t   length;
 uint16_t   callid;
 uint16_t   seq; /* optional based on flags */
 uint16_t   ack; /* optional based on flags */
} __attribute__ ((packed));
typedef struct gre_frame gre_frame_t;
#define GRE_SIZE (sizeof(gre_frame_t))
#define GRE_MIN_SIZE (sizeof(gre_frame_t) - 4)
#define GREPROTO_PPP 0x880b
#define GRE_FLAG_SYNSET 0x0010
#define GRE_FLAG_ACKSET 0x8000


struct ppp_frame
{
 uint16_t   proto;
} __attribute__ ((packed));
typedef struct ppp_frame ppp_frame_t;
#define PPP_SIZE sizeof(ppp_frame_t)
#define PPPPROTO_CHAP 0xc223


struct pppchap_frame
{
 uint8_t    code;
 uint8_t    identifier;
 uint16_t   length;
 union
 {
 struct
  {
   uint8_t    datalen;
   uint8_t    serverchallenge[16];
   uint8_t    names;
  } challenge;
 struct
  {
   uint8_t    datalen;
   uint8_t    clientchallenge[16];
   uint8_t    unknown[8]; /* all zero's */
   uint8_t    authresponse[24];
   uint8_t    status;
   uint8_t    namec;
  } response;
 } u;
} __attribute__ ((packed));
typedef struct pppchap_frame pppchap_frame_t;
#define PPPCHAPHDR_SIZE 4
#define PPPCHAPHDR_MIN_CHAL_SIZE 21
#define PPPCHAPHDR_MIN_RESP_SIZE 55
#define PPPCHAP_CHALLENGE   1
#define PPPCHAP_RESPONSE    2
#define PPPCHAP_SUCCESS     3
#define PPPCHAP_FAILURE     4


#define MYREPLAYCOUNT 63232

#define	MESSAGE_PAIR_M12E2 0
#define	MESSAGE_PAIR_M14E4 1
#define	MESSAGE_PAIR_M32E2 2
#define	MESSAGE_PAIR_M32E3 3
#define	MESSAGE_PAIR_M34E3 4
#define	MESSAGE_PAIR_M34E4 5

#define	MESSAGE_PAIR_M12E2NR 128
#define	MESSAGE_PAIR_M14E4NR 129
#define	MESSAGE_PAIR_M32E2NR 130
#define	MESSAGE_PAIR_M32E3NR 131
#define	MESSAGE_PAIR_M34E3NR 132
#define	MESSAGE_PAIR_M34E4NR 133


struct hcx
{
 uint32_t signature;
 uint32_t version;
 uint8_t  message_pair;
 uint8_t  essid_len;
 uint8_t  essid[32];
 uint8_t  keyver;
 uint8_t  keymic[16];
 adr_t    mac_ap;
 uint8_t  nonce_ap[32];
 adr_t    mac_sta;
 uint8_t  nonce_sta[32];
 uint16_t eapol_len;
 uint8_t  eapol[256];
} __attribute__((packed));
typedef struct hcx hcx_t;
#define	HCX_SIZE (sizeof(hcx_t))


struct hc5500
{
 adr_t    mac_ap1;
 adr_t    mac_sta1;
 adr_t    mac_ap2;
 adr_t    mac_sta2;
 uint8_t  p1;
 uint8_t  p2;
 uint8_t  leapid1;
 uint8_t  leapid2;
 char     username[258];
 uint8_t  peerchallenge[8];
 uint8_t  peerresponse[24];
} __attribute__((packed));
typedef struct hc5500 hc5500_t;


struct hc5500chap
{
 adr_t    mac_ap1;
 adr_t    mac_sta1;
 adr_t    mac_ap2;
 adr_t    mac_sta2;
 uint8_t  id1;
 uint8_t  id2;
 uint8_t  p1;
 uint8_t  p2;
 uint8_t  serverchallenge[16];
 uint8_t  clientchallenge[16];
 uint8_t  authchallenge[8];
 uint8_t  authresponse[24];
 char     usernames[258];
 char     usernamec[258];
} __attribute__((packed));
typedef struct hc5500chap hc5500chap_t;


struct hc4800
{
 adr_t    mac_ap1;
 adr_t    mac_sta1;
 adr_t    mac_ap2;
 adr_t    mac_sta2;
 uint8_t  id1;
 uint8_t  id2;
 uint8_t  p1;
 uint8_t  p2;
 uint8_t  challenge[16];
 uint8_t  response[16];
} __attribute__((packed));
typedef struct hc4800 hc4800_t;


struct netdb
{
 long int	tv_sec;
 long int	tv_usec;
 adr_t		mac_ap;
 adr_t		mac_sta;
 uint8_t	essid_len;
 uint8_t	essid[34];
};
typedef struct netdb netdb_t;
#define	NETDB_SIZE (sizeof(netdb_t))

struct eapdb
{
 long int	tv_sec;
 time_t		tv_usec;
 adr_t		mac_ap;
 adr_t		mac_sta;
 uint16_t	eapol_len;
 uint8_t	eapol[256];
};
typedef struct eapdb eapdb_t;
#define	EAPDB_SIZE (sizeof(eapdb_t))


struct hcxhrc
{
 uint32_t salt_buf[64];
 uint32_t pke[32];
 uint32_t eapol[64 + 16];
 uint32_t keymic[4];
};
typedef struct hcxhrc hcxhrc_t;

#ifdef __APPLE__
#define be64toh(n) (((n) << 56) | (((n) & 0xff00) << 40) | (((n) & 0xff0000) << 24) | (((n) & 0xff000000) << 8) | (((n) >> 8) & 0xff000000) | (((n) >> 24) & 0xff0000) | (((n) >> 40) & 0xff00) | ((n) >> 56))
#endif

/*===========================================================================*/
/* globale Konstante */

extern const uint8_t channellist[];
extern const uint8_t mynonce[];

const uint8_t channellist[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 ,14,
36, 40, 44, 48, 52, 56, 60, 64,
100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
149, 153, 157, 161, 165
};
#define CHANNELLIST_SIZE sizeof(channellist)


const uint8_t mynonce[] =
{
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9
};
#define ANONCE_SIZE sizeof(anonce)

/*===========================================================================*/

uint32_t rotl32(uint32_t a, uint32_t n);
uint64_t rotl64(uint64_t a, uint64_t n);
uint32_t rotr32(uint32_t a, uint32_t n);
uint64_t rotr64(uint64_t a, uint64_t n);
uint16_t byte_swap_16 (uint16_t n);
uint32_t byte_swap_32(uint32_t n);
uint64_t byte_swap_64(uint64_t n);

bool hexstr2bin(const char *str, uint8_t *bytes, size_t blen);
void uint8t2hex_lower(uint8_t v, uint8_t hex[2]);
void do_hexify (uint8_t *buf, int len, uint8_t *out);
void do_full_hexify (uint8_t *buf, int len, uint8_t *out);
uint8_t hex_convert(uint8_t c);
uint8_t hex2uint8t(uint8_t hex[2]);
bool is_valid_hex_char(uint8_t c);
bool is_valid_hex_string(uint8_t *s, int len);
int do_unhexify(uint8_t *in_buf, int in_len, uint8_t *out_buf, int out_size);
bool is_hexify(uint8_t *in_buf, int len);
bool is_printable_ascii (uint8_t *in_buf, int len);
bool need_hexify(uint8_t *in_buf, int len);

int mystrlen(uint8_t *in_buf);

int countdelimiter(uint8_t *in_buf, char delimiter);
int getdelimiterpos(uint8_t *in_buf, char delimiter);


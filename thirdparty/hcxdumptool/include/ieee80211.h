#define MYREPLAYCOUNT 63232

#define	MAC_SIZE_ACK		(10)
#define	MAC_SIZE_RTS		(16)
#define	MAC_SIZE_NORM		(24)
#define	MAC_SIZE_QOS		(26)
#define	MAC_SIZE_LONG		(30)
#define	MAC_SIZE_QOS_LONG	(32)

#define FCS_LEN 4

/* types */
#define IEEE80211_FTYPE_MGMT		0x0
#define IEEE80211_FTYPE_CTL		0x1
#define IEEE80211_FTYPE_DATA		0x2
#define IEEE80211_FTYPE_RCVD		0x3

/* management */
#define IEEE80211_STYPE_ASSOC_REQ	0x0
#define IEEE80211_STYPE_ASSOC_RESP	0x1
#define IEEE80211_STYPE_REASSOC_REQ	0x2
#define IEEE80211_STYPE_REASSOC_RESP	0x3
#define IEEE80211_STYPE_PROBE_REQ	0x4
#define IEEE80211_STYPE_PROBE_RESP	0x5
#define IEEE80211_STYPE_BEACON		0x8
#define IEEE80211_STYPE_ATIM		0x9
#define IEEE80211_STYPE_DISASSOC	0xa
#define IEEE80211_STYPE_AUTH		0xb
#define IEEE80211_STYPE_DEAUTH		0xc
#define IEEE80211_STYPE_ACTION		0xd

/* control */
#define IEEE80211_STYPE_CTL_EXT		0x6
#define IEEE80211_STYPE_BACK_REQ	0x8
#define IEEE80211_STYPE_BACK		0x9
#define IEEE80211_STYPE_PSPOLL		0xa
#define IEEE80211_STYPE_RTS		0xb
#define IEEE80211_STYPE_CTS		0xc
#define IEEE80211_STYPE_ACK		0xd
#define IEEE80211_STYPE_CFEND		0xe
#define IEEE80211_STYPE_CFENDACK	0xf

/* data */
#define IEEE80211_STYPE_DATA			0x0
#define IEEE80211_STYPE_DATA_CFACK		0x1
#define IEEE80211_STYPE_DATA_CFPOLL		0x2
#define IEEE80211_STYPE_DATA_CFACKPOLL		0x3
#define IEEE80211_STYPE_NULLFUNC		0x4
#define IEEE80211_STYPE_CFACK			0x5
#define IEEE80211_STYPE_CFPOLL			0x6
#define IEEE80211_STYPE_CFACKPOLL		0x7
#define IEEE80211_STYPE_QOS_DATA		0x8
#define IEEE80211_STYPE_QOS_DATA_CFACK		0x9
#define IEEE80211_STYPE_QOS_DATA_CFPOLL		0xa
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0xb
#define IEEE80211_STYPE_QOS_NULLFUNC		0xc
#define IEEE80211_STYPE_QOS_CFACK		0xd
#define IEEE80211_STYPE_QOS_CFPOLL		0xe
#define IEEE80211_STYPE_QOS_CFACKPOLL		0xf

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
/*===========================================================================*/
struct radiotap_header
{
 uint8_t	it_version;
 uint8_t	it_pad;
 uint16_t	it_len;
 uint32_t	it_present;
} __attribute__((__packed__));
typedef struct radiotap_header rth_t;
#define	RTH_SIZE (sizeof(rth_t))
/*===========================================================================*/
struct ethernet2_header
{
 uint8_t	addr1[6];
 uint8_t	addr2[6];
 uint16_t	ether_type;
} __attribute__((packed));
typedef struct ethernet2_header eth2_t;
#define	ETH2_SIZE (sizeof(eth2_t))
/*===========================================================================*/
struct loopback_header
{
 uint32_t		family;
} __attribute__((packed));
typedef struct loopback_header loba_t;
#define	LOBA_SIZE (sizeof(loba_t))
/*===========================================================================*/
#define WLAN_DEVNAMELEN_MAX 16
struct prism_item
{
 uint32_t did;
 uint16_t status;
 uint16_t len;
 uint32_t data;
} __attribute__((packed));

struct prism_header
{
 uint32_t msgcode;
 uint32_t msglen;
 char devname[WLAN_DEVNAMELEN_MAX];
 struct prism_item hosttime;
 struct prism_item mactime;
 struct prism_item channel;
 struct prism_item rssi;
 struct prism_item sq;
 struct prism_item signal;
 struct prism_item noise;
 struct prism_item rate;
 struct prism_item istx;
 struct prism_item frmlen;
} __attribute__((packed));
typedef struct prism_item prism_item_t;
typedef struct prism_header prism_t;
#define	PRISM_SIZE (sizeof(prism_t))

/*===========================================================================*/
struct avs_header
{
  uint32_t version;
  uint32_t len;
  uint64_t mactime;
  uint64_t hosttime;
  uint32_t phytype;
  uint32_t channel;
  uint32_t datarate;
  uint32_t antenna;
  uint32_t priority;
  uint32_t ssi_type;
  int32_t ssi_signal;
  int32_t ssi_noise;
  uint32_t preamble;
  uint32_t encoding;
} __attribute__((packed));
typedef struct avs_header avs_t;
#define	AVS_SIZE (sizeof(avs_t))
/*===========================================================================*/
struct ppi_header
{
 uint8_t  pph_version;
 uint8_t  pph_flags;
 uint16_t pph_len;
 uint32_t pph_dlt;
} __attribute__((packed));
typedef struct ppi_header ppi_t;
#define	PPI_SIZE (sizeof(ppi_t))
/*===========================================================================*/
struct msnetmon_header
{
 uint8_t	version_minor;
 uint8_t	version_major;
 uint16_t	network;
 uint16_t	ts_year;
 uint16_t	ts_month;
 uint16_t	ts_weekday;
 uint16_t	ts_day;
 uint16_t	ts_hour;
 uint16_t	ts_min;
 uint16_t	ts_sec;
 uint16_t	ts_msec;
 uint32_t	frametableoffset;
 uint32_t	frametablelength;
 uint32_t	userdataoffset;
 uint32_t	userdatalength;
 uint32_t	commentdataoffset;
 uint32_t	commentdatalength;
 uint32_t	statisticsoffset;
 uint32_t	statisticslength;
 uint32_t	networkinfooffset;
 uint32_t	networkinfolength;
} __attribute__((packed));
typedef struct msnetmon_header msntm_t;
#define MSNETMON_SIZE (sizeof(msntm_t))
/*===========================================================================*/
struct fcs_frame
{
 uint32_t	fcs;
};
typedef struct fcs_frame fcs_t;
#define	FCS_SIZE (sizeof(fcs_t))
/*===========================================================================*/
struct qos_frame
{
 uint8_t	control;
 uint8_t	flags;
} __attribute__((__packed__));
typedef struct qos_frame qos_t;
#define	QOS_SIZE (sizeof(qos_t))
/*===========================================================================*/
/*
 * DS bit usage
 *
 * TA = transmitter address
 * RA = receiver address
 * DA = destination address
 * SA = source address
 *
 * ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
 * -----------------------------------------------------------------
 *  0       0       DA      SA      BSSID   -       IBSS/DLS
 *  0       1       DA      BSSID   SA      -       AP -> STA
 *  1       0       BSSID   SA      DA      -       AP <- STA
 *  1       1       RA      TA      DA      SA      unspecified (WDS)
 */
struct mac_frame
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
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
 uint8_t	addr1[6];
 uint8_t	addr2[6];
 uint8_t	addr3[6];
 uint16_t	sequence;
 uint8_t	addr4[6];
 qos_t		qos;
} __attribute__((__packed__));
typedef struct mac_frame mac_t;
/*===========================================================================*/
struct capabilities_ap_frame
{
 uint64_t	timestamp;
 uint16_t	beaconintervall;
 uint16_t	capabilities;
} __attribute__((__packed__));
typedef struct capabilities_ap_frame capap_t;
#define	CAPABILITIESAP_SIZE sizeof(capap_t)
/*===========================================================================*/
struct capabilities_sta_frame
{
 uint16_t capabilities;
 uint16_t listeninterval;
} __attribute__((__packed__));
typedef struct capabilities_sta_frame capsta_t;
#define	CAPABILITIESSTA_SIZE sizeof(capsta_t)
/*===========================================================================*/
struct capabilitiesreq_sta_frame
{
 uint16_t 	capabilities;
 uint16_t 	listeninterval;
 uint8_t	addr[6];
} __attribute__((__packed__));
typedef struct capabilitiesreq_sta_frame capreqsta_t;
#define	CAPABILITIESREQSTA_SIZE sizeof(capreqsta_t)
/*===========================================================================*/
struct ie_tag
{
 uint8_t		id;
#define	TAG_SSID	0x00
#define	TAG_RATE	0x01
#define	TAG_CHAN	0x03
#define	TAG_RSN		0x30
 uint8_t		len;
 uint8_t		data[1];
} __attribute__((__packed__));
typedef struct ie_tag ietag_t;
#define	IETAG_SIZE offsetof(ietag_t, data)
/*===========================================================================*/
struct rsn_tag
{
 uint8_t	id;
 uint8_t	len;
 uint16_t	version;
} __attribute__((__packed__));
typedef struct rsn_tag rsntag_t;
#define	RSNTAG_SIZE sizeof(rsntag_t)
/*===========================================================================*/
struct vendor_tag
{
 uint8_t	tagnr;
 uint8_t	taglen;
 uint8_t	oui[3];
 uint8_t	data[1];
} __attribute__ ((packed));
typedef struct vendor_tag vendor_t;
#define	VENDORTAG_SIZE offsetof(vendor_t, data)
#define VENDORTAG_AUTH_SIZE 0x0b
/*===========================================================================*/
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
#define	LLC_SNAP 0xaa
/*===========================================================================*/
struct authentication_frame
{
 uint16_t	authentication_algho;
#define OPEN_SYSTEM 0
#define SHARED_KEY 1
#define FBT 2
#define SAE 3
#define FILS 4
#define FILSPFS 5
#define FILSPK 6
#define NETWORKEAP 128
 uint16_t	authentication_seq;
 uint16_t	statuscode;
} __attribute__((__packed__));
typedef struct authentication_frame authf_t;
#define	AUTHENTICATIONFRAME_SIZE (sizeof(authf_t))
/*===========================================================================*/
struct sae_commit_authentication_frame
{
 uint16_t	group_id;
 uint8_t	scalar[32];
 uint8_t	commit_element_x[32];
 uint8_t	commit_element_y[32];
} __attribute__((__packed__));
typedef struct sae_commit_authentication_frame saecommitauthf_t;
#define	SAECOMMITAUTHENTICATIONFRAME_SIZE (sizeof(saecommitauthf_t))
/*===========================================================================*/
struct sae_confirm_authentication_frame
{
 uint16_t	send_confirm;
 uint8_t	confirm[32];
} __attribute__((__packed__));
typedef struct sae_confirm_authentication_frame saeconfirmauthf_t;
#define	SAECONFIRMAUTHENTICATIONFRAME_SIZE (sizeof(saeconfirmauthf_t))
/*===========================================================================*/

struct association_resp_frame
{
 uint16_t	capabilities;
 uint16_t	authentication_seq;
 uint16_t	statuscode;
 uint16_t	id;
} __attribute__((__packed__));
typedef struct association_resp_frame assocrepf_t;
#define	ASSOCIATIONRESPFRAME_SIZE (sizeof(assocrepf_t))
/*===========================================================================*/
struct action_frame
{
 uint8_t	categoriecode;
#define CAT_BLOCK_ACK		3
#define CAT_RADIO_MEASUREMENT		5
 uint8_t	actioncode;
#define ACT_ADD_BLOCK_ACK_REQ		0
#define ACT_ADD_BLOCK_ACK_RESP		0
#define ACT_DELETE_BLOCK_REQ		2
#define ACT_RADIO_MEASUREMENT_REQ	0
};
typedef struct action_frame actf_t;
#define ACTIONFRAME_SIZE (sizeof(actf_t))
/*===========================================================================*/
struct eapauthentication_frame
{
 uint8_t	version;
 uint8_t	type;
#define EAP_PACKET 0
#define EAPOL_START 1
#define EAPOL_LOGOFF 2
#define EAPOL_KEY 3
#define EAPOL_ASF 4
#define EAPOL_MKA 5
 uint16_t	len;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct eapauthentication_frame eapauth_t;
#define	EAPAUTH_SIZE offsetof(eapauth_t, data)
/*===========================================================================*/
struct wpakey_frame
{
 uint8_t	keydescriptor;
 uint16_t	keyinfo;
 uint16_t	keylen;
 uint64_t	replaycount;
 uint8_t	nonce[32];
 uint8_t	keyiv[16];
 uint64_t	keyrsc;
 uint8_t	keyid[8];
 uint8_t	keymic[16];
 uint16_t	wpadatalen;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct wpakey_frame wpakey_t;
#define	WPAKEY_SIZE offsetof(wpakey_t, data)
/*===========================================================================*/
struct pmkid_frame
{
 uint8_t	id;
 uint8_t	len;
 uint8_t	oui[3];
 uint8_t	type;
 uint8_t	pmkid[16];
} __attribute__((__packed__));
typedef struct pmkid_frame pmkid_t;
#define	PMKID_SIZE (sizeof(pmkid_t))
/*===========================================================================*/
struct exteap_frame
{
 uint8_t			code;
#define EAP_CODE_REQ		1
#define EAP_CODE_RESP		2
#define EAP_CODE_SUCCESS	3
#define EAP_CODE_FAILURE	4
#define EAP_CODE_INITIATE	5
#define EAP_CODE_FINISH		6
 uint8_t			id;
#define EAP_TYPE_ID		1
 uint16_t			extlen;
 uint8_t			exttype;
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
 uint8_t			data[1];
} __attribute__((__packed__));
typedef struct exteap_frame exteap_t;
#define	EXTEAP_SIZE offsetof(exteap_t, data)
/*===========================================================================*/
struct eapleap_frame
{
 uint8_t	code;
 uint8_t	id;
 uint16_t	len;
 uint8_t	type;
 uint8_t	version;
 uint8_t	reserved;
 uint8_t	count;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct eapleap_frame eapleap_t;
#define	EAPLEAP_SIZE offsetof(eapleap_t, data)
/*===========================================================================*/
struct mpdu_frame
{
 uint8_t pn[3];
 uint8_t keyid;
 uint8_t exitiv[4];
};
typedef struct mpdu_frame mpdu_t;
#define	MPDU_SIZE (sizeof(mpdu_t))
/*===========================================================================*/
struct md5_frame
{
 uint8_t	code;
 uint8_t	id;
 uint16_t	len;
 uint8_t	type;
 uint8_t	data_len;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct md5_frame md5_t;
#define	MD5_SIZE offsetof(md5_t, data)
/*===========================================================================*/
struct ipv4_frame
{
 uint8_t	ver_hlen;
 uint8_t	tos;
 uint16_t	len;
 uint16_t	ipid;
 uint16_t	flags_offset;
 uint8_t	ttl;
 uint8_t	nextprotocol;
#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_ICMP4		1	/* ICMP4 header */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP6		58	/* ICMP6 for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */
#define NEXTHDR_MAX		255
 uint16_t	checksum;
 uint8_t	srcaddr[4];
 uint8_t	dstaddr[4];
} __attribute__ ((packed));
typedef struct ipv4_frame ipv4_t;
#define	IPV4_SIZE (sizeof(ipv4_t))
#define	IPV4_SIZE_MIN 20
#define	IPV4_SIZE_MAX 64
/*===========================================================================*/
struct ipv6_frame
{
 uint32_t	ver_class;
 uint16_t	len;
 uint8_t	nextprotocol;
 uint8_t	hoplimint;
 uint8_t	srcaddr[16];
 uint8_t	dstaddr[16];
} __attribute__ ((packed));
typedef struct ipv6_frame ipv6_t;
#define	IPV6_SIZE (sizeof(ipv6_t))
/*===========================================================================*/
struct tcp_frame
{
 uint16_t	sourceport;
 uint16_t	destinationport;
 uint32_t	sequencenumber;
 uint32_t	acknumber;
 uint8_t	len /* x 4 */;
 uint8_t	flags;
 uint16_t	window;
 uint16_t	checksum;
 uint16_t	urgent;
 uint8_t	options[1];
} __attribute__ ((packed));
typedef struct tcp_frame tcp_t;
#define	TCP_SIZE_MIN offsetof(tcp_t, options)
/*===========================================================================*/
struct udp_frame
{
 uint16_t	sourceport;
 uint16_t	destinationport;
#define UDP_DHCP_SERVERPORT 67
#define UDP_DHCP_CLIENTPORT 68
#define UDP_DHCP6_SERVERPORT 547
#define UDP_DHCP6_CLIENTPORT 546
#define UDP_RADIUS_DESTINATIONPORT 1812
#define UDP_TZSP_DESTINATIONPORT 37008
 uint16_t	len;
 uint16_t	checksum;
} __attribute__ ((packed));
typedef struct udp_frame udp_t;
#define	UDP_SIZE (sizeof(udp_t))

/*===========================================================================*/
struct tzsp_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	enc_protocol;
#define TZSP_ENCAP_ETHERNET		1
#define TZSP_ENCAP_TOKEN_RING		2
#define TZSP_ENCAP_SLIP			3
#define TZSP_ENCAP_PPP			4
#define TZSP_ENCAP_FDDI			5
#define TZSP_ENCAP_RAW			7
#define TZSP_ENCAP_IEEE_802_11		18
#define TZSP_ENCAP_IEEE_802_11_PRISM	119
#define TZSP_ENCAP_IEEE_802_11_AVS	127
 uint8_t	data[1];
} __attribute__ ((packed));
typedef struct tzsp_frame tzsp_t;
#define	TZSP_SIZE offsetof(tzsp_t, data)
/*===========================================================================*/
struct tzsp_tag
{
 uint8_t	tag;
#define TZSP_TAG_END 1
#define TZSP_TAG_ORGLEN 41

 uint8_t	len;
 uint8_t	data[1];
} __attribute__ ((packed));
typedef struct tzsp_tag tzsptag_t;
#define	TZSPTAG_SIZE offsetof(tzsptag_t, data)
/*===========================================================================*/
struct gre_frame
{
 uint16_t	flags;
 uint16_t	type;
 uint16_t	len;
 uint16_t	callid;
} __attribute__ ((packed));
typedef struct gre_frame gre_t;
#define GRE_SIZE (sizeof(gre_t))
#define GREPROTO_PPP 0x880b
#define GRE_FLAG_SNSET 0x1000
#define GRE_FLAG_ACKSET 0x0080
#define GRE_MASK_VERSION 0x0003
/*===========================================================================*/
struct ptp_frame
{
 uint16_t	type;
} __attribute__ ((packed));
typedef struct ptp_frame ptp_t;
#define PTP_SIZE (sizeof(ptp_t))
#define PROTO_PAP	0xc023
#define PROTO_CHAP	0xc223
/*===========================================================================*/
struct chap_frame
{
 uint8_t	code;
#define	CHAP_CODE_REQ	1
#define	CHAP_CODE_RESP	2

 uint8_t	id;
 uint16_t	len;
 uint8_t	data[1];
} __attribute__ ((packed));
typedef struct chap_frame chap_t;
#define CHAP_SIZE (sizeof(chap_t))
/*===========================================================================*/
struct tacacsp_frame
{
 uint8_t   version;
#define TACACSP_VERSION 0xc0
 uint8_t   type;
#define TACACS_AUTHENTICATION 1
 uint8_t   sequencenr;
 uint8_t   flags;
 uint32_t  sessionid;
 uint32_t  len;
 uint8_t   data[1];
} __attribute__ ((packed));
typedef struct tacacsp_frame tacacsp_t;
#define	TACACSP_SIZE offsetof(tacacsp_t, data)
/*===========================================================================*/
#define RADIUS_AUTHENTICATOR_LENGTH 16
#define RADIUS_PASSWORD_BLOCK_SIZE 16
#define RADIUS_HEADER_LENGTH 20
#define RADIUS_MAX_SIZE 1000
#define RADIUS_MAX_ATTRIBUTE_SIZE 253
struct radius_frame_t
{
 uint8_t	code;
 uint8_t	id;
 uint16_t	length;
 uint8_t	authenticator[RADIUS_AUTHENTICATOR_LENGTH];
 uint8_t	attrs[RADIUS_MAX_SIZE -RADIUS_HEADER_LENGTH];
 uint8_t	data[1];
} __attribute__ ((packed));
typedef struct radius_frame_t radius_t;
#define	RADIUS_SIZE offsetof(radius_t, data)
/*===========================================================================*/
/* global var */
static const uint8_t nulliv[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#define	NULLIV_SIZE (sizeof(nulliv))

static const uint8_t nullnonce[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define	NULLNONCE_SIZE (sizeof(nullnonce))

static const uint8_t mynonce[] =
{
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9
};
#define ANONCE_SIZE sizeof(anonce)

static const uint8_t mac_broadcast[] =
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t mac_null[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const int myvendorap[] =
{
0x00006c, 0x000101, 0x00054f, 0x000578, 0x000b18, 0x000bf4, 0x000c53, 0x000d58,
0x000da7, 0x000dc2, 0x000df2, 0x000e17, 0x000e22, 0x000e2a, 0x000eef, 0x000f09,
0x0016b4, 0x001761, 0x001825, 0x002067, 0x00221c, 0x0022f1, 0x00234a, 0x00238c,
0x0023f7, 0x002419, 0x0024fb, 0x00259d, 0x0025df, 0x00269f, 0x005047, 0x005079,
0x0050c7, 0x0084ed, 0x0086a0, 0x00a054, 0x00a085, 0x00bb3a, 0x00cb00, 0x0418b6,
0x0c8112, 0x100000, 0x10ae60, 0x10b713, 0x1100aa, 0x111111, 0x140708, 0x146e0a,
0x18421d, 0x1cf4ca, 0x205b2a, 0x20d160, 0x24336c, 0x24bf74, 0x28ef01, 0x3cb87a,
0x487604, 0x48f317, 0x50e14a, 0x544e45, 0x580943, 0x586ed6, 0x5c6b4f, 0x609620,
0x68e166, 0x706f81, 0x78f944, 0x7ce4aa, 0x8c8401, 0x8ce748, 0x906f18, 0x980ee4,
0x9c93e4, 0xa468bc, 0xa4a6a9, 0xacde48, 0xb025aa, 0xb0ece1, 0xb0febd, 0xb4e1eb,
0xc02250, 0xc8aacc, 0xd85dfb, 0xdc7014, 0xe00db9, 0xe0cb1d, 0xe80410, 0xf04f7c
};
#define MYVENDORAP_SIZE sizeof(myvendorap)

static const int myvendorsta[] =
{
0xf0a225, 0xfcc233
};
#define MYVENDORSTA_SIZE sizeof(myvendorsta)
/*===========================================================================*/

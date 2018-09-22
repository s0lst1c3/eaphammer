#define ERRORMAX 100000

#define ESSID_LEN_MAX 32
#define RSN_LEN_MAX 24
#define TIME_INTERVAL 5
#define EAPOLTIMEOUT 150000
#define M1WAITTIME 1000
#define DEAUTHENTICATIONINTERVALL 10
#define DEAUTHENTICATIONS_MAX 100
#define APATTACKSINTERVALL 10
#define APPATTACKS_MAX 100

#define FILTERLIST_MAX 64
#define FILTERLIST_LINE_LEN 0xff

#define APLIST_MAX 0xfff
#define MYAPLIST_MAX 0xfff
#define POWNEDLIST_MAX 0xfff

#define PROBEREQUESTLIST_MAX 512
#define MYPROBERESPONSELIST_MAX 512

#define CS_BROADCOM 1
#define CS_APPLE_BROADCOM 2
#define CS_SONOS 3
#define CS_NETGEARBROADCOM 4
#define CS_WILIBOX 5
#define CS_CISCO 6
#define CS_ENDE 7

#define RX_M1		0b00000001
#define RX_M12		0b00000010
#define RX_PMKID	0b00000100
#define RX_M23		0b00001000

#define STATUS_EAPOL		0b00000001
#define STATUS_PROBES		0b00000010
#define STATUS_AUTH		0b00000100
#define STATUS_ASSOC		0b00001000
#define STATUS_BEACON		0b00010000

#define HCXD_HELP			1
#define HCXD_VERSION			2
#define HCXD_FILTERLIST			3
#define HCXD_FILTERMODE			4
#define HCXD_DISABLE_ACTIVE_SCAN	5
#define HCXD_DISABLE_DEAUTHENTICATIONS	6
#define HCXD_GIVE_UP_DEAUTHENTICATIONS	7
#define HCXD_DISABLE_DISASSOCIATIONS	8
#define HCXD_DISABLE_AP_ATTACKS		9
#define HCXD_GIVE_UP_AP_ATTACKS		10
#define HCXD_DISABLE_CLIENT_ATTACKS	11
#define HCXD_STATION_VENDOR		12
#define HCXD_DO_RCASCAN			13
#define HCXD_SAVE_RCASCAN		14
#define HCXD_SAVE_RCASCAN_RAW		15
#define HCXD_ENABLE_STATUS		16

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

/*===========================================================================*/
struct aplist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 int		count;
 uint8_t	addr[6];
 uint8_t	channel;
 int		essid_len;
 uint8_t	essid[ESSID_LEN_MAX];
 int		rsn_len;
 uint8_t	rsn[RSN_LEN_MAX];
};
typedef struct aplist_s aplist_t;
#define	APLIST_SIZE (sizeof(aplist_t))

static int sort_aplist_by_time(const void *a, const void *b)
{
const aplist_t *ia = (const aplist_t *)a;
const aplist_t *ib = (const aplist_t *)b;
return (ia->timestamp < ib->timestamp);
}

static int sort_aplist_by_essid(const void *a, const void *b)
{
const aplist_t *ia = (const aplist_t *)a;
const aplist_t *ib = (const aplist_t *)b;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct myaplist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 uint8_t	addr[6];
 int		essid_len;
 uint8_t	essid[ESSID_LEN_MAX];
};
typedef struct myaplist_s myaplist_t;
#define	MYAPLIST_SIZE (sizeof(myaplist_t))

static int sort_myaplist_by_time(const void *a, const void *b)
{
const myaplist_t *ia = (const myaplist_t *)a;
const myaplist_t *ib = (const myaplist_t *)b;
return (ia->timestamp < ib->timestamp);
}
/*===========================================================================*/
struct maclist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 uint8_t	addr[6];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))
/*===========================================================================*/
struct macmaclist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 uint8_t	addr1[6];
 uint8_t	addr2[6];
};
typedef struct macmaclist_s macmaclist_t;
#define	MACMACLIST_SIZE (sizeof(macmaclist_t))

static int sort_macmaclist_by_time(const void *a, const void *b)
{
const macmaclist_t *ia = (const macmaclist_t *)a;
const macmaclist_t *ib = (const macmaclist_t *)b;
if(ia->timestamp < ib->timestamp)
	return 1;
else if(ia->timestamp > ib->timestamp)
	return -1;
return 0;
}
/*===========================================================================*/

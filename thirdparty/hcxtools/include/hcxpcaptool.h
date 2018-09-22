/*===========================================================================*/
struct apstaessidlist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint8_t	status;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	essidlen;
 uint8_t	essid[32];
} __attribute__((__packed__));
typedef struct apstaessidlist_s apstaessidl_t;
#define	APSTAESSIDLIST_SIZE (sizeof(apstaessidl_t))
/*===========================================================================*/
static int sort_apstaessidlist_by_ap_sta(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
static int sort_apstaessidlist_by_ap_essid(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
static int sort_apstaessidlist_by_ap_sta_essid(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
static int sort_apstaessidlist_by_essid(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct eapollist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo;
 uint64_t	replaycount;
 uint8_t	authlen;
 uint8_t	eapol[256];
} __attribute__((__packed__));
typedef struct eapollist_s eapoll_t;
#define	EAPOLLIST_SIZE (sizeof(eapoll_t))

/*===========================================================================*/
struct pmkidlist_s
{
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	pmkid[16];
} __attribute__((__packed__));
typedef struct pmkidlist_s pmkidl_t;
#define	PMKIDLIST_SIZE (sizeof(pmkidl_t))
/*===========================================================================*/
struct hcxtoollist_s
{
 uint64_t	tv_ea;
 uint64_t	tv_eo;
 uint64_t	tv_diff;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo_ap;
 uint8_t	keyinfo_sta;
 uint64_t	rc_diff;
 uint64_t	replaycount_ap;
 uint64_t	replaycount_sta;
 uint8_t	endianess;
 uint8_t	nonce[32];
 uint8_t	authlen;
 uint8_t	eapol[256];
 uint8_t	essidlen;
 uint8_t	essid[32];
} __attribute__((__packed__));
typedef struct hcxtoollist_s hcxl_t;
#define	HCXLIST_SIZE (sizeof(hcxl_t))
/*===========================================================================*/
struct leaplist_s
{
 uint8_t	code;
 uint8_t	id;
 uint8_t	len;
 uint8_t	data[0xff];
 uint16_t	username_len;
 uint8_t	username[0xff];
} __attribute__((__packed__));
typedef struct leaplist_s leapl_t;
#define	LEAPLIST_SIZE (sizeof(leapl_t))
/*===========================================================================*/
struct md5list_s
{
 uint8_t	code;
 uint8_t	id;
 uint8_t	len;
 uint8_t	data[0xff];
} __attribute__((__packed__));
typedef struct md5list_s md5l_t;
#define	MD5LIST_SIZE (sizeof(md5l_t))
/*===========================================================================*/
struct tacacsplist_s
{
 uint8_t	version;
 uint8_t	sequencenr;
 uint32_t	sessionid;
 uint32_t	len;
 uint8_t	data[0xff];
} __attribute__((__packed__));
typedef struct tacacsplist_s tacacspl_t;
#define	TACACSPLIST_SIZE (sizeof(tacacspl_t))
/*===========================================================================*/


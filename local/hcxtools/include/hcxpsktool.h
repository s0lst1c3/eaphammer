#define ESSID_LEN_MAX 32
#define PMKID_LINE_LEN 255
#define PSKSTRING_LEN_MAX 64

#define HCXD_HELP			1
#define HCXD_VERSION			2

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

/*===========================================================================*/
struct apessidlist_s
{
 uint8_t	status;
 unsigned long long int	macaddr;
 uint8_t	essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
} __attribute__((__packed__));
typedef struct apessidlist_s apessidl_t;
#define	APESSIDLIST_SIZE (sizeof(apessidl_t))
/*===========================================================================*/
static int sort_apessidlist_by_ap(const void *a, const void *b)
{
const apessidl_t *ia = (const apessidl_t *)a;
const apessidl_t *ib = (const apessidl_t *)b;
if(ia->macaddr > ib->macaddr)
	return 1;
if(ia->macaddr < ib->macaddr)
	return -1;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;

return 0;
}
/*===========================================================================*/
static int sort_apessidlist_by_essid(const void *a, const void *b)
{
const apessidl_t *ia = (const apessidl_t *)a;
const apessidl_t *ib = (const apessidl_t *)b;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;
if(ia->macaddr > ib->macaddr)
	return 1;
if(ia->macaddr < ib->macaddr)
	return -1;
return 0;
}
/*===========================================================================*/

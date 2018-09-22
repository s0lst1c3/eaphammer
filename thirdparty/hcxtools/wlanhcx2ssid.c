#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#ifdef __APPLE__
#include <libgen.h>
#include <sys/types.h> /* This in turn sources machine/endian.h */
#else
#include <endian.h>
#include <stdio_ext.h>
#endif

#include "include/version.h"
#include "common.h"

/*===========================================================================*/
/* globale Variablen */

static hcx_t *hcxdata = NULL;
static const uint8_t nullnonce[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define	NULLNONCE_SIZE (sizeof(nullnonce))

/*===========================================================================*/
static size_t chop(char *buffer,  size_t len)
{
char *ptr = buffer +len -1;

while (len) {
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}

while (len) {
	if (*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if (feof(inputstream)) return -1;
		char *buffptr = fgets (buffer, size, inputstream);

	if (buffptr == NULL) return -1;

	size_t len = strlen(buffptr);
	len = chop(buffptr, len);

return len;
}
/*===========================================================================*/
static uint8_t geteapkey(uint8_t *eapdata)
{
eap_t *eap;
uint16_t keyinfo;
int eapkey = 0;

eap = (eap_t*)(uint8_t*)(eapdata);
keyinfo = (((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8));
if (keyinfo & WPA_KEY_INFO_ACK)
	{
	if(keyinfo & WPA_KEY_INFO_INSTALL)
		{
		/* handshake 3 */
		eapkey = 3;
		}
	else
		{
		/* handshake 1 */
		eapkey = 1;
		}
	}
else
	{
	if(keyinfo & WPA_KEY_INFO_SECURE)
		{
		/* handshake 4 */
		eapkey = 4;
		}
	else
		{
		/* handshake 2 */
		eapkey = 2;
		}
	}
return eapkey;
}
/*===========================================================================*/
static uint8_t geteapkeyver(uint8_t *eapdata)
{
const eap_t *eap;
int eapkeyver;

eap = (const eap_t*)(uint8_t*)(eapdata);
eapkeyver = ((((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8)) & WPA_KEY_INFO_TYPE_MASK);
return eapkeyver;
}
/*===========================================================================*/
static unsigned long long int getreplaycount(uint8_t *eapdata)
{
const eap_t *eap;
unsigned long long int replaycount = 0;

eap = (const eap_t*)(uint8_t*)(eapdata);
replaycount = be64toh(eap->replaycount);
return replaycount;
}
/*===========================================================================*/
static int sort_by_ap_record(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 6) < 0)
	return -1;
if(memcmp(ia->nonce_ap, ib->nonce_ap, 28) > 0)
	return 1;
else if(memcmp(ia->nonce_ap, ib->nonce_ap, 28) < 0)
	return -1;
if(ia->message_pair > ib->message_pair)
	return 1;
if(ia->message_pair < ib->message_pair)
	return -1;
return 0;
}
/*===========================================================================*/
static int writermdupes(long int hcxrecords, char *rmdupesname)
{
hcx_t *zeigerhcx, *zeigerhcxold;
FILE *fhhcx;
long int c;
long int rw = 0;
long int removedcount = 0;

if(hcxrecords == 0)
	{
	return false;
	}
qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_ap_record);
if((fhhcx = fopen(rmdupesname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", rmdupesname);
	return false;
	}
fwrite(hcxdata, HCX_SIZE, 1, fhhcx);
c = 1;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	zeigerhcxold = hcxdata +c -1;
	if(memcmp(zeigerhcx->mac_ap.addr, zeigerhcxold->mac_ap.addr, 6) == 0)
		{
		if(memcmp(zeigerhcx->mac_sta.addr, zeigerhcxold->mac_sta.addr, 6) == 0)
			{
			if(memcmp(zeigerhcx->nonce_ap, zeigerhcxold->nonce_ap, 28) == 0)
				{
				if(memcmp(zeigerhcx->essid, zeigerhcxold->essid, 32) == 0)
					{
					removedcount++;
					c++;
					continue;
					}
				}
			}
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	c++;
	rw++;
	}
fclose(fhhcx);
printf("%ld records removed\n%ld records written to %s\n", removedcount, rw +1, rmdupesname);
return true;
}
/*===========================================================================*/
static int writerepaired(long int hcxrecords, char *repairedname)
{
hcx_t *zeigerhcx;
eap_t *eap;
uint8_t keynr = 0;
long int c;
long int rw = 0;
long int rwerr = 0;
FILE *fhhcx;

uint8_t fakeanonce[] =
{
0x07, 0xbc, 0x92, 0xea, 0x2f, 0x5a, 0x1e, 0xe2, 0x54, 0xf6, 0xb1, 0xb7, 0xe0, 0xaa, 0xd3, 0x53,
0xf4, 0x5b, 0x0a, 0xac, 0xf9, 0xc9, 0x90, 0x2f, 0x90, 0xd8, 0x78, 0x80, 0xb7, 0x03, 0x0a, 0x20
};

uint8_t fakesnonce[] =
{
0x95, 0x30, 0xd1, 0xc7, 0xc3, 0x55, 0xb9, 0xab, 0xe6, 0x83, 0xd6, 0xf3, 0x7e, 0xcb, 0x78, 0x02,
0x75, 0x1f, 0x53, 0xcc, 0xb5, 0x81, 0xd1, 0x52, 0x3b, 0xb4, 0xba, 0xad, 0x23, 0xab, 0x01, 0x07
};

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	keynr = geteapkey(zeigerhcx->eapol);
	if(keynr == 1)
		{
		rwerr++;
		c++;
		continue;
		}
	if(memcmp(&nullnonce, zeigerhcx->nonce_ap, 32) == 0)
		{
		rwerr++;
		c++;
		continue;
		}
	if(memcmp(&nullnonce, zeigerhcx->nonce_sta, 32) == 0)
		{
		rwerr++;
		c++;
		continue;
		}
	if((memcmp(&fakesnonce, zeigerhcx->nonce_sta, 32) == 0) && (memcmp(&fakeanonce, zeigerhcx->nonce_ap, 32) == 0) && (getreplaycount(zeigerhcx->eapol) == 17))
		{
		rwerr++;
		c++;
		continue;
		}
	if((memcmp(&fakeanonce, zeigerhcx->nonce_sta, 32) == 0) && (memcmp(&fakesnonce, zeigerhcx->nonce_ap, 32) == 0) && (getreplaycount(zeigerhcx->eapol) == 17))
		{
		rwerr++;
		c++;
		continue;
		}
	if((memcmp(&mynonce, zeigerhcx->nonce_ap, 32) == 0) && (getreplaycount(zeigerhcx->eapol) != MYREPLAYCOUNT))
		{
		rwerr++;
		c++;
		continue;
		}
	if((memcmp(&mynonce, zeigerhcx->nonce_sta, 32) == 0) && (getreplaycount(zeigerhcx->eapol) != MYREPLAYCOUNT))
		{
		rwerr++;
		c++;
		continue;
		}
	eap = (eap_t*)zeigerhcx->eapol;
	if(ntohs(eap->wpadatalen) > (ntohs(eap->len) -95))
		{
		rwerr++;
		c++;
		continue;
		}

	if((fhhcx = fopen(repairedname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", repairedname);
		return false;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	rw++;
	c++;
	}
printf("%ld records precessed\n%ld damaged records stripped\n", rw, rwerr);

return true;
}
/*===========================================================================*/
static int writekeyver(long int hcxrecords, char *keyvername)
{
hcx_t *zeigerhcx;
uint8_t keyver = 0;
long int c;
long int rw = 0;
FILE *fhhcx;
char keyveroutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
		{
		keyver = geteapkeyver(zeigerhcx->eapol);
		sprintf(keyveroutname, "%s.%x.hccapx", keyvername, keyver);
		if((fhhcx = fopen(keyveroutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", keyveroutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		fclose(fhhcx);
		rw++;
		}
	c++;
	}
printf("%ld records precessed\n", rw);
return true;
}
/*===========================================================================*/
static int sort_by_mac_staessid(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
static int writesinglenet1hccapx(long int hcxrecords, char *singlenetname)
{
hcx_t *zeigerhcx, *zeigerhcxa;
long int c;
long int rw = 0;
FILE *fhhcx = NULL;

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_mac_staessid);
if((fhhcx = fopen(singlenetname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", singlenetname);
	return false;
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(c > 0)
		{
		zeigerhcxa = hcxdata +c -1;
		if((memcmp(zeigerhcx->mac_sta.addr, zeigerhcxa->mac_sta.addr, 6) != 0) || (memcmp(zeigerhcx->essid, zeigerhcxa->essid, 32) != 0))
			{
			fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
			rw++;
			}
		}
	else
		{
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		}

	c++;
	}

fclose(fhhcx);

printf("%ld records written to %s\n", rw, singlenetname);
return true;
}
/*===========================================================================*/
static int sort_by_macs(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) < 0)
	return -1;
if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 6) < 0)
	return -1;
if(ia->message_pair > ib->message_pair)
	return 1;
if(ia->message_pair < ib->message_pair)
	return -1;
return 0;
}
/*===========================================================================*/
static int writesinglenethccapx(long int hcxrecords, char *singlenetname)
{
hcx_t *zeigerhcx, *zeigerhcxa;
long int c;
long int rw = 0;
FILE *fhhcx = NULL;

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_macs);
if((fhhcx = fopen(singlenetname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", singlenetname);
	return false;
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(c > 0)
		{
		zeigerhcxa = hcxdata +c -1;
		if((memcmp(zeigerhcx->mac_ap.addr, zeigerhcxa->mac_ap.addr, 6) != 0) || (memcmp(zeigerhcx->mac_sta.addr, zeigerhcxa->mac_sta.addr, 6) != 0) || (zeigerhcx->message_pair != zeigerhcxa->message_pair) || (memcmp(zeigerhcx->essid, zeigerhcxa->essid, 32) != 0))
			{
			fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
			rw++;
			}
		}
	else
		{
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		}

	c++;
	}

fclose(fhhcx);

printf("%ld records written to %s\n", rw, singlenetname);
return true;
}
/*===========================================================================*/
static int writemessagepairhccapx(long int hcxrecords, char *mpname, uint8_t message_pair)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(zeigerhcx->message_pair == message_pair)
		{
		if((fhhcx = fopen(mpname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", mpname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, mpname);
return true;
}
/*===========================================================================*/
static uint8_t getpwgpinfo(uint8_t *eapdata)
{
const eap_t *eap;
int eapkeyver;

eap = (const eap_t*)(uint8_t*)(eapdata);
eapkeyver = ((((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8)) & WPA_KEY_INFO_KEY_TYPE);
return eapkeyver;
}
/*===========================================================================*/
static int writegroupkeysethccapx(long int hcxrecords, char *groupkeyname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(getpwgpinfo(zeigerhcx->eapol) == 0)
		{
		if((fhhcx = fopen(groupkeyname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", groupkeyname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, groupkeyname);
return true;
}
/*===========================================================================*/
static int writepairwisesethccapx(long int hcxrecords, char *pairwisekeyname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(getpwgpinfo(zeigerhcx->eapol) == 8)
		{
		if((fhhcx = fopen(pairwisekeyname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", pairwisekeyname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, pairwisekeyname);
return true;
}
/*===========================================================================*/
static int writercnotcheckedhccapx(long int hcxrecords, char *rcnotckeckedname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if((zeigerhcx->message_pair &0x80) == 0x80)
		{
		if((fhhcx = fopen(rcnotckeckedname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", rcnotckeckedname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, rcnotckeckedname);
return true;
}
/*===========================================================================*/
static int writerccheckedhccapx(long int hcxrecords, char *rcckeckedname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if((zeigerhcx->message_pair &0x80) == 0)
		{
		if((fhhcx = fopen(rcckeckedname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", rcckeckedname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, rcckeckedname);
return true;
}
/*===========================================================================*/
static int writewantessidlenhccapx(long int hcxrecords, int essidlen)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
FILE *fhhcx;


char wantessidlenoutname[PATH_MAX +1];
snprintf(wantessidlenoutname, PATH_MAX, "%d.hccapx", essidlen);

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(zeigerhcx->essid_len == essidlen)
		{
		if((fhhcx = fopen(wantessidlenoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", wantessidlenoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, wantessidlenoutname);
return true;
}
/*===========================================================================*/
static int writewlandumpnotforcedhccapx(long int hcxrecords, char *wlandumpforcedname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
unsigned long long int r;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	r = getreplaycount(zeigerhcx->eapol);
	if((memcmp(&mynonce, zeigerhcx->nonce_ap, 32) != 0) && (r != MYREPLAYCOUNT))
		{

		if((fhhcx = fopen(wlandumpforcedname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", wlandumpforcedname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, wlandumpforcedname);
return true;
}
/*===========================================================================*/
static int writewlandumpforcedhccapx(long int hcxrecords, char *wlandumpforcedname)
{
hcx_t *zeigerhcx;
long int c;
long int rw = 0;
unsigned long long int r;
FILE *fhhcx;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	r = getreplaycount(zeigerhcx->eapol);
	if((memcmp(&mynonce, zeigerhcx->nonce_ap, 32) == 0) && (r == MYREPLAYCOUNT))
		{
		if((fhhcx = fopen(wlandumpforcedname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", wlandumpforcedname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written to %s\n", rw, wlandumpforcedname);
return true;
}
/*===========================================================================*/
static int writemacaplisthccapx(long int hcxrecords, char *aplistname, char *apoutname)
{
adr_t mac;
hcx_t *zeigerhcx;
FILE *fhaplist;
FILE *fhhcx;
unsigned long long int mac_ap;
long int c;
long int rw = 0;
int len;

char linein[14];

if((fhaplist = fopen(aplistname, "r")) == NULL)
	{
	fprintf(stderr, "error opening file %s", aplistname);
	return false;
	}

while((len = fgetline(fhaplist, 14, linein)) != -1)
	{
	if(len != 12)
		continue;

	mac_ap = strtoul(linein, NULL, 16);
	mac.addr[5] = mac_ap & 0xff;
	mac.addr[4] = (mac_ap >> 8) & 0xff;
	mac.addr[3] = (mac_ap >> 16) & 0xff;
	mac.addr[2] = (mac_ap >> 24) & 0xff;
	mac.addr[1] = (mac_ap >> 32) & 0xff;
	mac.addr[0] = (mac_ap >> 40) & 0xff;
	c = 0;
	while(c < hcxrecords)
		{
		zeigerhcx = hcxdata +c;
		if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 6) == 0)
			{
			if((fhhcx = fopen(apoutname, "ab")) == NULL)
				{
				fprintf(stderr, "error opening file %s", apoutname);
				fclose(fhaplist);
				return false;
				}
			fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
			rw++;
			fclose(fhhcx);
			}
		c++;
		}
	}

printf("%ld records written to %s\n", rw, apoutname);
fclose(fhaplist);
return true;
}
/*===========================================================================*/
static int writesearchouihccapx(long int hcxrecords, unsigned long long int oui)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
adr_t mac;

char macoutname[PATH_MAX +1];

snprintf(macoutname, PATH_MAX, "%06llx.hccapx", oui);

mac.addr[2] = oui & 0xff;
mac.addr[1] = (oui >> 8) & 0xff;
mac.addr[0] = (oui >> 16) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 3) == 0)
		{
		if((fhhcx = fopen(macoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", macoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writesearchvendorhccapx(long int hcxrecords, unsigned long long int oui, char *vendorstring)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
adr_t mac;
const char *hccapxstr = ".hccapx";

char vendoroutname[PATH_MAX +1];

strcpy(vendoroutname, vendorstring);
strcat(vendoroutname,hccapxstr);
if((fhhcx = fopen(vendoroutname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", vendoroutname);
	return false;
	}

mac.addr[2] = oui & 0xff;
mac.addr[1] = (oui >> 8) & 0xff;
mac.addr[0] = (oui >> 16) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 3) == 0)
		{
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		}
	c++;
	}

fclose(fhhcx);
if(rw > 0)
	printf("%06llx: %ld records written to %s\n", oui, rw, vendoroutname);
return true;
}
/*===========================================================================*/
static void writesearchvendornamehccapx(long int hcxrecords, char *vendorstring)
{
int len;
uid_t uid;
struct passwd *pwd;
FILE* fhoui;
unsigned long long int vendoroui;

const char ouiname[] = "/.hcxtools/oui.txt";

char ouipathname[PATH_MAX +1];
char linein[256];

uid = getuid();
pwd = getpwuid(uid);
if (pwd == NULL)
	{
	fprintf(stdout, "failed to get home dir\n");
	exit(EXIT_FAILURE);
	}

strcpy(ouipathname, pwd->pw_dir);
strcat(ouipathname, ouiname);

if ((fhoui = fopen(ouipathname, "r")) == NULL)
	{
	fprintf(stderr, "unable to open database %s\n", ouipathname);
	exit (EXIT_FAILURE);
	}

while((len = fgetline(fhoui, 256, linein)) != -1)
	{
	if (len < 10)
		continue;

	if(strstr(linein, "(base 16)") != NULL)
		{
		if(strstr(linein, vendorstring) != NULL)
			{
			sscanf(linein, "%06llx", &vendoroui);
			writesearchvendorhccapx(hcxrecords, vendoroui, vendorstring);
			}
		}
	}
fclose(fhoui);
return;
}
/*===========================================================================*/
static int writesearchmacstahccapx(long int hcxrecords, unsigned long long int mac_sta)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
adr_t mac;

char macoutname[PATH_MAX +1];

snprintf(macoutname, PATH_MAX, "%012llx.hccapx", mac_sta);

mac.addr[5] = mac_sta & 0xff;
mac.addr[4] = (mac_sta >> 8) & 0xff;
mac.addr[3] = (mac_sta >> 16) & 0xff;
mac.addr[2] = (mac_sta >> 24) & 0xff;
mac.addr[1] = (mac_sta >> 32) & 0xff;
mac.addr[0] = (mac_sta >> 40) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_sta.addr, 6) == 0)
		{
		if((fhhcx = fopen(macoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", macoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writesearchmacaphccapx(long int hcxrecords, unsigned long long int mac_ap)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
adr_t mac;

char macoutname[PATH_MAX +1];

snprintf(macoutname, PATH_MAX, "%012llx.hccapx", mac_ap);

mac.addr[5] = mac_ap & 0xff;
mac.addr[4] = (mac_ap >> 8) & 0xff;
mac.addr[3] = (mac_ap >> 16) & 0xff;
mac.addr[2] = (mac_ap >> 24) & 0xff;
mac.addr[1] = (mac_ap >> 32) & 0xff;
mac.addr[0] = (mac_ap >> 40) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 6) == 0)
		{
		if((fhhcx = fopen(macoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", macoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writesearchessidhccapx(long int hcxrecords, char *essidname)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
char essidoutname[PATH_MAX +1];

char essidstr[34];

snprintf(essidoutname, PATH_MAX, "%s.hccapx", essidname);
c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&essidstr, 0, 34);
	memcpy(&essidstr, zeigerhcx->essid, zeigerhcx->essid_len);
	if(strstr(essidstr, essidname) != NULL)
		{
		if((fhhcx = fopen(essidoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", essidoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writesearchessidxhccapx(long int hcxrecords, char *essidxname)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
char essidxoutname[PATH_MAX +1];

char essidstr[34];

snprintf(essidxoutname, PATH_MAX, "%s.hccapx", essidxname);
c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&essidstr, 0, 34);
	memcpy(&essidstr, zeigerhcx->essid, zeigerhcx->essid_len);
	if(strcmp(essidstr, essidxname) == 0)
		{
		if((fhhcx = fopen(essidxoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", essidxoutname);
			return false;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		rw++;
		fclose(fhhcx);
		}
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
static int writeessidhccapx(long int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
int cei, ceo;

char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	ceo = 0;
	for (cei = 0; cei < zeigerhcx->essid_len; cei++)
		{
		hcxoutname[ceo] = digit[(zeigerhcx->essid[cei] & 0xff) >> 4];
		ceo++;
		hcxoutname[ceo] = digit[zeigerhcx->essid[cei] & 0x0f];
		ceo++;
		}
	hcxoutname[ceo] = 0;
	strcat(&hcxoutname[ceo], ".hccapx");
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return false;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	rw++;
	fclose(fhhcx);
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static void oui2hxoutname(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x.hccapx",p[0],p[1],p[2]);
return;
}
/*===========================================================================*/
static void mac2hxoutname(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x%02x%02x%02x.hccapx",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
static int writeouiaphccapx(long int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;
char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	oui2hxoutname(hcxoutname, zeigerhcx->mac_ap.addr);
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return false;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	rw++;
	fclose(fhhcx);
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writemacstahccapx(long int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;

char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	mac2hxoutname(hcxoutname, zeigerhcx->mac_sta.addr);
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return false;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	rw++;
	fclose(fhhcx);
	c++;
	}
printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static int writemacaphccapx(long int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
long int rw = 0;

char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	mac2hxoutname(hcxoutname, zeigerhcx->mac_ap.addr);
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return false;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	rw++;
	fclose(fhhcx);
	c++;
	}

printf("%ld records written\n", rw);
return true;
}
/*===========================================================================*/
static long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return false;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return 0;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return 0;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return 0;
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		fclose(fhhcx);
		return 0;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
fclose(fhhcx);
if(hcxsize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return 0;
	}
hcxsize /= HCX_SIZE;
printf("%ld records read from %s\n", hcxsize, hcxinname);
return hcxsize;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file>     : input hccapx file\n"
	"-p <path>     : change directory for outputfiles\n"
	"-a            : output file by mac_ap's\n"
	"-s            : output file by mac_sta's\n"
	"-o            : output file by vendor's (oui)\n"
	"-e            : output file by essid's\n"
	"-E <essid>    : output file by part of essid name\n"
	"-X <essid>    : output file by essid name (exactly)\n"
	"-x <digit>    : output by essid len (0 <= 32)\n"
	"-A <mac_ap>   : output file by single mac_ap\n"
	"-S <mac_sta>  : output file by single mac_sta\n"
	"-O <oui>      : output file by single vendor (oui)\n"
	"-V <name>     : output file by single vendor name or part of vendor name\n"
	"-L <mac_list> : input list containing mac_ap's (need -l)\n"
	"              : format of mac_ap's each line: 112233445566\n"
	"-l <file>     : output file (hccapx) by mac_list (need -L)\n"
	"-w <file>     : write only forced from clients to hccapx file\n"
	"-W <file>     : write only forced from access points to hccapx file\n"
	"-r <file>     : write only replaycount checked to hccapx file\n"
	"-R <file>     : write only not replaycount checked to hccapx file\n"
	"-N <file>     : output stripped file (only one record each mac_ap, mac_sta, essid, message_pair combination)\n"
	"-n <file>     : output stripped file (only one record each mac_sta, essid)\n"
	"-g <file>     : write only handshakes with pairwise key flag set\n"
	"-G <file>     : write only handshakes with groupkey flag set\n"
	"-0 <file>     : write only MESSAGE_PAIR_M12E2 to hccapx file\n"
	"-1 <file>     : write only MESSAGE_PAIR_M14E4 to hccapx file\n"
	"-2 <file>     : write only MESSAGE_PAIR_M32E2 to hccapx file\n"
	"-3 <file>     : write only MESSAGE_PAIR_M32E3 to hccapx file\n"
	"-4 <file>     : write only MESSAGE_PAIR_M34E3 to hccapx file\n"
	"-5 <file>     : write only MESSAGE_PAIR_M34E4 to hccapx file\n"
	"-k <file>     : write keyversion based on key information field (use only basename)\n"
	"              : output: basename.x.hccapx\n"
	"              : WPA1 RC4 Cipher, HMAC-MD5..... basename.1.hccapx\n"
	"              : WPA2 AES Cipher, HMAC-SHA1.... basename.2.hccapx\n"
	"              : WPA2 AES Cipher, AES-128-CMAC2 basename.3.hccapx\n"
	"              : all other are unknown\n"
	"-F <file>     : remove bad records and write only flawless records to hccapx file\n"
	"-D <file>     : remove duplicates from the same authentication sequence\n"
	"              : you must use nonce-error-corrections on that file!\n"
	"-h            : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int mode = 0;
int retchdir = 0;
int wantessidlen = 1;
long int hcxorgrecords = 0;
unsigned long long int mac_ap = 0;
unsigned long long int mac_sta = 0;
unsigned long long int oui = 0;
uint8_t message_pair = 0;

char *hcxinname = NULL;
char *essidname = NULL;
char *essidxname = NULL;
char *aplistname = NULL;
char *apoutname = NULL;
char *wlandumpforcedname = NULL;
char *rccheckedname = NULL;
char *rcnotcheckedname = NULL;
char *mpname = NULL;
char *keyvername = NULL;
char *singlenetname = NULL;
char *singlenetname1 = NULL;
char *vendorname = NULL;
char *groupkeyname = NULL;
char *pairwisekeyname = NULL;
char *workingdirname = NULL;
char *wdres;
char *repairedname = NULL;
char *rmdupesname = NULL;
char workingdir[PATH_MAX +1];

setbuf(stdout, NULL);
wdres = getcwd(workingdir, PATH_MAX);
if(wdres != NULL)
	workingdirname = workingdir;
while ((auswahl = getopt(argc, argv, "i:A:S:O:V:E:X:x:p:l:L:w:W:r:R:N:n:g:G:0:1:2:3:4:5:k:F:D:asoeh")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'a':
		mode = 'a';
		break;

		case 's':
		mode = 's';
		break;

		case 'o':
		mode = 'o';
		break;

		case 'e':
		mode = 'e';
		break;

		case 'p':
		workingdirname = optarg;
		break;

		case 'E':
		essidname = optarg;
		if(strlen(essidname) > 32)
			{
			fprintf(stderr, "essid > 32\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'X':
		essidxname = optarg;
		if(strlen(essidxname) > 32)
			{
			fprintf(stderr, "essid > 32\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'x':
		wantessidlen = strtoul(optarg, NULL, 10);
		if((wantessidlen < 0) || (wantessidlen > 32))
			{
			fprintf(stderr, "essid > 32\n");
			exit(EXIT_FAILURE);
			}

		mode = 'x';
		break;

		case 'A':
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "error wrong mac size %s (need 112233aabbcc)\n", optarg);
			exit(EXIT_FAILURE);
			}
		mac_ap = strtoul(optarg, NULL, 16);
		mode = 'A';
		break;

		case 'S':
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "error wrong mac size %s (need 112233aabbcc)\n", optarg);
			exit(EXIT_FAILURE);
			}
		mac_sta = strtoul(optarg, NULL, 16);
		mode = 'S';
		break;

		case 'O':
		if(strlen(optarg) != 6)
			{
			fprintf(stderr, "error wrong oui size %s (need 1122aa)\n", optarg);
			exit(EXIT_FAILURE);
			}
		oui = strtoul(optarg, NULL, 16);
		mode = 'O';
		break;

		case 'V':
		vendorname = optarg;
		mode = 'V';
		break;

		case 'l':
		apoutname = optarg;
		break;

		case 'L':
		aplistname = optarg;
		mode = 'L';
		break;

		case 'w':
		wlandumpforcedname = optarg;
		mode = 'w';
		break;

		case 'W':
		wlandumpforcedname = optarg;
		mode = 'W';
		break;

		case 'r':
		rccheckedname = optarg;
		mode = 'r';
		break;

		case 'R':
		rcnotcheckedname = optarg;
		mode = 'R';
		break;

		case 'N':
		singlenetname = optarg;
		mode = 'N';
		break;

		case 'n':
		singlenetname1 = optarg;
		mode = 'n';
		break;

		case 'g':
		pairwisekeyname = optarg;
		mode = 'g';
		break;

		case 'G':
		groupkeyname = optarg;
		mode = 'G';
		break;

		case '0':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M12E2;
		break;

		case '1':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M14E4;
		break;

		case '2':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M32E2;
		break;

		case '3':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M32E3;
		break;

		case '4':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M34E3;
		break;

		case '5':
		mpname = optarg;
		mode = 'M';
		message_pair = MESSAGE_PAIR_M34E4;
		break;

		case 'k':
		keyvername = optarg;
		mode = 'k';
		break;

		case 'F':
		repairedname = optarg;
		mode = 'F';
		break;

		case 'D':
		rmdupesname = optarg;
		mode = 'D';
		break;

		default:
		usage(basename(argv[0]));
		}
	}

hcxorgrecords = readhccapx(hcxinname);
if(hcxorgrecords == 0)
	return EXIT_SUCCESS;

retchdir = chdir(workingdirname);
if(retchdir != 0)
	fprintf(stderr, " couldn't change working directory to %s\nusing %s\n", workingdirname, workingdir);

if(mode == 'a')
	writemacaphccapx(hcxorgrecords);

else if(mode == 's')
	writemacstahccapx(hcxorgrecords);

else if(mode == 'o')
	writeouiaphccapx(hcxorgrecords);

else if(mode == 'e')
	writeessidhccapx(hcxorgrecords);

else if(mode == 'A')
	writesearchmacaphccapx(hcxorgrecords, mac_ap);

else if(mode == 'S')
	writesearchmacstahccapx(hcxorgrecords, mac_sta);

else if(mode == 'O')
	writesearchouihccapx(hcxorgrecords, oui);

else if(mode == 'V')
	writesearchvendornamehccapx(hcxorgrecords, vendorname);

else if(essidname != NULL)
	writesearchessidhccapx(hcxorgrecords, essidname);

else if(mode == 'x')
	writewantessidlenhccapx(hcxorgrecords, wantessidlen);

else if(essidxname != NULL)
	writesearchessidxhccapx(hcxorgrecords, essidxname);

else if(mode == 'L')
	{
	if((aplistname != NULL) && (apoutname != 0))
		writemacaplisthccapx(hcxorgrecords, aplistname, apoutname);
	else
		{
		fprintf(stderr, "need -L (input list of mac_ap's to strip and -l output file (hccapx)\n");
		exit(EXIT_FAILURE);
		}
	}

else if(mode == 'w')
	{
	if(wlandumpforcedname != NULL)
		writewlandumpforcedhccapx(hcxorgrecords, wlandumpforcedname);
	}

else if(mode == 'W')
	{
	if(wlandumpforcedname != NULL)
		writewlandumpnotforcedhccapx(hcxorgrecords, wlandumpforcedname);
	}

else if(mode == 'r')
	{
	if(rccheckedname != NULL)
		writerccheckedhccapx(hcxorgrecords, rccheckedname);
	}

else if(mode == 'N')
	{
	if(singlenetname != NULL)
		writesinglenethccapx(hcxorgrecords, singlenetname);
	}

else if(mode == 'n')
	{
	if(singlenetname1 != NULL)
		writesinglenet1hccapx(hcxorgrecords, singlenetname1);
	}

else if(mode == 'R')
	{
	if(rcnotcheckedname != NULL)
		writercnotcheckedhccapx(hcxorgrecords, rcnotcheckedname);
	}

else if(mode == 'M')
	{
	if(mpname != NULL)
		writemessagepairhccapx(hcxorgrecords, mpname, message_pair);
	}

else if(mode == 'g')
	{
	if(pairwisekeyname != NULL)
		writepairwisesethccapx(hcxorgrecords, pairwisekeyname);
	}

else if(mode == 'G')
	{
	if(groupkeyname != NULL)
		writegroupkeysethccapx(hcxorgrecords, groupkeyname);
	}


else if(mode == 'k')
	{
	if(keyvername != NULL)
		writekeyver(hcxorgrecords, keyvername);
	}

else if(mode == 'F')
	{
	if(repairedname != NULL)
		writerepaired(hcxorgrecords, repairedname);
	}

else if(mode == 'D')
	{
	if(rmdupesname != NULL)
		writermdupes(hcxorgrecords, rmdupesname);
	}


if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

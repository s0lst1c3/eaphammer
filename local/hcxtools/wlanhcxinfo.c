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
#include <sys/stat.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif

#include "include/version.h"
#include "common.h"

#define OM_MAC_AP	0b000000000000000001
#define OM_MAC_STA	0b000000000000000010
#define OM_MESSAGE_PAIR	0b000000000000000100
#define OM_NONCE_AP	0b000000000000001000
#define OM_NONCE_STA	0b000000000000010000
#define OM_KEYMIC	0b000000000000100000
#define OM_REPLAYCOUNT	0b000000000001000000
#define OM_KEYVER	0b000000000010000000
#define OM_KEYTYPE	0b000000000100000000
#define OM_ESSID_LEN	0b000000001000000000
#define OM_ESSID	0b000000010000000000

#define LINEBUFFER	1024
#define ARCH_INDEX(x)	((unsigned int)(unsigned char)(x))

struct hccap
{
  char essid[36];
  unsigned char mac1[6];	/* bssid */
  unsigned char mac2[6];	/* client */
  unsigned char nonce1[32];	/* snonce client */
  unsigned char nonce2[32];	/* anonce bssid */
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))



/*===========================================================================*/
/* globale Variablen */

static hcx_t *hcxdata = NULL;

static const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static unsigned char atoi64[0x100];
/*===========================================================================*/
/* globale Initialisierung */

static void globalinit(void)
{
const char *pos;
memset(atoi64, 0x7F, sizeof(atoi64));
for (pos = itoa64; pos <= &itoa64[63]; pos++)
	atoi64[ARCH_INDEX(*pos)] = pos - itoa64;
return;
}
/*===========================================================================*/
static void printhex(const uint8_t *buffer, int size)
{
int c;
for (c = 0; c < size; c++)
	fprintf(stdout, "%02x", buffer[c]);
return;
}
/*===========================================================================*/
static int checkessid(uint8_t essid_len, uint8_t *essid)
{
uint8_t p;

if(essid_len == 0)
	return false;

if(essid_len > 32)
	return false;

for(p = 0; p < essid_len; p++)
	if((essid[p] < 0x20) || (essid[p] > 0x7e))
		return false;
return true;
}
/*===========================================================================*/
static uint8_t geteapkeytype(uint8_t *eapdata)
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
static uint8_t get8021xver(uint8_t *eapdata)
{
const eap_t *eap;
eap = (const eap_t*)(uint8_t*)(eapdata);
return eap->version;
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
static uint8_t getpwgpinfo(uint8_t *eapdata)
{
const eap_t *eap;
int eapkeyver;

eap = (const eap_t*)(uint8_t*)(eapdata);
eapkeyver = ((((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8)) & WPA_KEY_INFO_KEY_TYPE);
return eapkeyver;
}
/*===========================================================================*/
static unsigned long long int geteapreplaycount(uint8_t *eapdata)
{
const eap_t *eap;
unsigned long long int replaycount = 0;

eap = (const eap_t*)(uint8_t*)(eapdata);
replaycount = be64toh(eap->replaycount);
return replaycount;
}
/*===========================================================================*/
static int sort_by_nonce_ap(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

return memcmp(ia->nonce_ap, ib->nonce_ap, 32);
}
/*===========================================================================*/
static void writehcxinfo(long int hcxrecords, int outmode)
{
hcx_t *zeigerhcx;
long int c, c1;
uint8_t pf;
uint8_t eapver;
uint8_t keyver;
uint8_t pwgpinfo;
uint8_t keytype;

unsigned long long int replaycount;

long int totalrecords = 0;
long int wldcount = 0;
long int xverc1 = 0;
long int xverc2 = 0;
long int wpakv1c = 0;
long int wpakv2c = 0;
long int wpakv3c = 0;
long int groupkeycount = 0;

long int mp0c = 0;
long int mp1c = 0;
long int mp2c = 0;
long int mp3c = 0;
long int mp4c = 0;
long int mp5c = 0;
long int mple = 0;
long int mpbe = 0;
long int mp80c = 0;
long int mp81c = 0;
long int mp82c = 0;
long int mp83c = 0;
long int mp84c = 0;
long int mp85c = 0;
long int noessidcount = 0;

uint8_t noncecorr = false;

uint8_t nonceold[32] = {};
char essidoutstr[34];

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_nonce_ap);

c = 0;
while(c < hcxrecords)
	{
	pf = false;
	zeigerhcx = hcxdata +c;
	eapver = get8021xver(zeigerhcx->eapol);
	keyver = geteapkeyver(zeigerhcx->eapol);
	pwgpinfo = getpwgpinfo(zeigerhcx->eapol);
	if(keyver == 1)
		wpakv1c++;

	if(keyver == 2)
		wpakv2c++;

	if(keyver == 3)
		wpakv3c++;

	if((pwgpinfo) == 0)
		groupkeycount++;


	replaycount = geteapreplaycount(zeigerhcx->eapol);
	if((replaycount == MYREPLAYCOUNT) && (memcmp(&mynonce, zeigerhcx->nonce_ap, 32) == 0))
		wldcount++;

	if((memcmp(&nonceold, zeigerhcx->nonce_ap, 28) == 0) && (memcmp(&nonceold, zeigerhcx->nonce_ap, 32) != 0))
		noncecorr = true;
	memcpy(&nonceold, zeigerhcx->nonce_ap, 32);


	if((outmode & OM_MAC_AP) == OM_MAC_AP)
		{
		printhex(zeigerhcx->mac_ap.addr, 6);
		pf = true;
		}

	if((outmode & OM_NONCE_AP) == OM_NONCE_AP)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_ap, 32);
		pf = true;
		}

	if((outmode & OM_MAC_STA) == OM_MAC_STA)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->mac_sta.addr, 6);
		pf = true;
		}

	if((outmode & OM_NONCE_STA) == OM_NONCE_STA)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_sta, 32);
		pf = true;
		}

	if((outmode & OM_KEYMIC) == OM_KEYMIC)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->keymic, 16);
		pf = true;
		}

	if((outmode & OM_REPLAYCOUNT) == OM_REPLAYCOUNT)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%016llx", replaycount);
		pf = true;
		}

	if((outmode & OM_KEYVER) == OM_KEYVER)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%d", keyver);
		pf = true;
		}

	if((outmode & OM_KEYTYPE) == OM_KEYTYPE)
		{
		if(pf == true)
			fprintf(stdout, ":");
		keytype = geteapkeytype(zeigerhcx->eapol);
		fprintf(stdout, "%d", keytype);
		pf = true;
		}

	if((outmode & OM_MESSAGE_PAIR) == OM_MESSAGE_PAIR)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%02x", zeigerhcx->message_pair);
		pf = true;
		}

	if((outmode & OM_ESSID_LEN) == OM_ESSID_LEN)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%02d", zeigerhcx->essid_len);
		pf = true;
		}

	if((outmode & OM_ESSID) == OM_ESSID)
		{
		if(pf == true)
			fprintf(stdout, ":");

		if(zeigerhcx->essid_len > 32)
			zeigerhcx->essid_len = 32;
		memset(&essidoutstr, 0, 34);
		memcpy(&essidoutstr, zeigerhcx->essid, zeigerhcx->essid_len);

		if(checkessid(zeigerhcx->essid_len, zeigerhcx->essid) == true)
			fprintf(stdout, "%s", essidoutstr);

		else if(zeigerhcx->essid_len != 0)
			{
			fprintf(stdout, "$HEX[");
			for(c1 = 0; c1 < zeigerhcx->essid_len; c1++)
				fprintf(stdout, "%02x", zeigerhcx->essid[c1]);
			fprintf(stdout, "]");
			}
		else
			fprintf(stdout, "<empty ESSID>");

		}

	if((outmode) != 0)
		fprintf(stdout, "\n");

	if(eapver == 1)
		xverc1++;

	if(eapver == 2)
		xverc2++;

	if((zeigerhcx->message_pair & 0x03) == 0)
		{
		mp0c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp80c++;
		}

	if((zeigerhcx->message_pair & 0x03) == 1)
		{
		mp1c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp81c++;
		}

	if((zeigerhcx->message_pair & 0x03) == 2)
		{
		mp2c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp82c++;
		}

	if((zeigerhcx->message_pair & 0x07) == 3)
		{
		mp3c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp83c++;
		}

	if((zeigerhcx->message_pair & 0x07) == 4)
		{
		mp4c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp84c++;
		}

	if((zeigerhcx->message_pair & 0x07) == 5)
		{
		mp5c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
			mp85c++;
		}
	if((zeigerhcx->message_pair & 0x20) == 0x20)
		{
		mple++;
		}
	if((zeigerhcx->message_pair & 0x40) == 0x40)
		{
		mpbe++;
		}
	if((zeigerhcx->essid_len == 0) && (zeigerhcx->essid[0] == 0))
		noessidcount++;

	totalrecords++;
	c++;
	}

if(outmode == 0)
	{
	fprintf(stdout, "total hashes read from file.......: %ld\n"
			"\x1B[32mhandshakes from clients...........: %ld\x1B[0m\n"
			"little endian router detected.....: %ld\n"
			"big endian router detected........: %ld\n"
			"zeroed ESSID......................: %ld\n"
			"802.1x Version 2001...............: %ld\n"
			"802.1x Version 2004...............: %ld\n"
			"WPA1 RC4 Cipher, HMAC-MD5.........: %ld\n"
			"WPA2 AES Cipher, HMAC-SHA1........: %ld\n"
			"WPA2 AES Cipher, AES-128-CMAC.....: %ld\n"
			"group key flag set................: %ld\n"
			"message pair M12E2................: %ld (%ld not replaycount checked)\n"
			"message pair M14E4................: %ld (%ld not replaycount checked)\n"
			"message pair M32E2................: %ld (%ld not replaycount checked)\n"
			"message pair M32E3................: %ld (%ld not replaycount checked)\n"
			"message pair M34E3................: %ld (%ld not replaycount checked)\n"
			"message pair M34E4................: %ld (%ld not replaycount checked)"
			"\n", totalrecords, wldcount, mple, mpbe, noessidcount, xverc1, xverc2, wpakv1c, wpakv2c, wpakv3c, groupkeycount, mp0c, mp80c, mp1c, mp81c, mp2c, mp82c, mp3c, mp83c, mp4c, mp84c, mp5c, mp85c);

	if(noncecorr == true)
		fprintf(stdout, "\x1B[32mnonce-error-corrections is working on that file\x1B[0m\n");
	}

return;
}
/*===========================================================================*/
static bool processhc(hccap_t *zeiger, hcx_t *hcxrecord)
{
int essid_len;
uint8_t m;

char essidout[36];

memset(&essidout, 0, 36);
memcpy(&essidout, zeiger->essid, 36);
essid_len = strlen(essidout);
if((essid_len == 0) || (essid_len > 32) || (zeiger->essid[0] == 0))
	return false;

m = geteapkeytype(zeiger->eapol);
if((m < 2) || (m > 4))
	return false;

memset(hcxrecord, 0, HCX_SIZE);
hcxrecord->signature = HCCAPX_SIGNATURE;
hcxrecord->version = HCCAPX_VERSION;
hcxrecord->essid_len = essid_len;
if(m == 2)
	hcxrecord->message_pair = MESSAGE_PAIR_M12E2;
if(m == 3)
	hcxrecord->message_pair = MESSAGE_PAIR_M32E3;
if(m == 4)
	hcxrecord->message_pair = MESSAGE_PAIR_M14E4;
memcpy(hcxrecord->essid, zeiger->essid, essid_len);
hcxrecord->keyver = geteapkeyver(zeiger->eapol);
memcpy(hcxrecord->mac_ap.addr, zeiger->mac1, 6);
memcpy(hcxrecord->nonce_ap, zeiger->nonce2, 32);
memcpy(hcxrecord->mac_sta.addr, zeiger->mac2, 6);
memcpy(hcxrecord->nonce_sta, zeiger->nonce1, 32);
hcxrecord->eapol_len = zeiger->eapol_size;
memcpy(hcxrecord->eapol, zeiger->eapol, zeiger->eapol_size +4);
memcpy(hcxrecord->keymic, zeiger->keymic, 16);
memset(&hcxrecord->eapol[0x51], 0, 16);


return true;
}
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
static long int readjohn(char *johninname)
{
int len;
int l;
int le;
int i;
long int hcxsize = 0;
struct stat statinfo;
FILE *fhjohn;
uint8_t *hcptr = NULL;
hccap_t *hc = NULL;
hcx_t *hcxz = NULL;
char *ptr = NULL;
char *ptre = NULL;
char *ptressid = NULL;
const char *formatstring = "$WPAPSK$";

char linein[LINEBUFFER];

unsigned char hctemp[HCCAP_SIZE];

if(stat(johninname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", johninname);
	return 0;
	}

if((fhjohn = fopen(johninname, "r")) == NULL)
	{
	fprintf(stderr, "unable to open database %s\n", johninname);
	exit (EXIT_FAILURE);
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		fclose(fhjohn);
		return 0;
		}


hcxz = hcxdata;
while((len = fgetline(fhjohn, LINEBUFFER, linein)) != -1)
	{
	if (len < 10)
		continue;

	ptressid = strstr(linein, formatstring);
	if(ptressid == NULL)
		continue;
	ptressid += 8;

	ptr = strrchr(linein, '#');
	if(ptr == NULL)
		continue;
	le = ptr - ptressid;
	ptr++;

	if(le > 32)
		continue;

	ptre = strchr(ptr, ':');
	if(ptre == NULL)
		continue;

	ptre[0] = 0;
	l = ptre - ptr;
	if(l != 475)
		continue;

	memset(&hctemp, 0, HCCAP_SIZE);
	memcpy(&hctemp, ptressid, le);
	hcptr = hctemp +36;
	for (i = 0; i < 118; i++)
		{
		hcptr[0] = (atoi64[ARCH_INDEX(ptr[0])] << 2) | (atoi64[ARCH_INDEX(ptr[1])] >> 4);
		hcptr[1] = (atoi64[ARCH_INDEX(ptr[1])] << 4) | (atoi64[ARCH_INDEX(ptr[2])] >> 2);
		hcptr[2] = (atoi64[ARCH_INDEX(ptr[2])] << 6) | (atoi64[ARCH_INDEX(ptr[3])]);
		hcptr += 3;
		ptr += 4;
		}
	hcptr[0] = (atoi64[ARCH_INDEX(ptr[0])] << 2) | (atoi64[ARCH_INDEX(ptr[1])] >> 4);
	hcptr[1] = (atoi64[ARCH_INDEX(ptr[1])] << 4) | (atoi64[ARCH_INDEX(ptr[2])] >> 2);
	hc = (hccap_t*)hctemp;
	if(processhc(hc, hcxz) == true)
		{
		hcxz++;
		hcxsize++;
		}
	}
fclose(fhjohn);
return hcxsize;
}
/*===========================================================================*/
static long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

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

hcxdata = malloc(statinfo.st_size +HCX_SIZE);
if(hcxdata == NULL)
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		fclose(fhhcx);
		return 0;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size, fhhcx);
fclose(fhhcx);
if(hcxsize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return 0;
	}
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"example: %s -i <hashfile> show general informations about file\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-j <file> : input john file (doesn't support all list options)\n"
	"-o <file> : output info file (default stdout)\n"
	"-a        : list access points\n"
	"-A        : list anonce\n"
	"-s        : list stations\n"
	"-S        : list snonce\n"
	"-M        : list key mic\n"
	"-R        : list replay count\n"
	"-w        : list wpa version\n"
	"-P        : list key key number\n"
	"-p        : list messagepair\n"
	"-l        : list essid len\n"
	"-e        : list essid\n"
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int outmode = 0;
long int hcxorgrecords = 0;

char *hcxinname = NULL;
char *johninname = NULL;
char *infoname = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:j:o:aAsSMRwpPlehv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'j':
		johninname = optarg;
		break;

		case 'o':
		infoname = optarg;
		FILE *fp = fopen(infoname,"w");
		if (fp == NULL)
			{
			fprintf(stderr, "unable to open outputfile %s\n", infoname);
			exit (EXIT_FAILURE);
			}
		fclose (fp);
		break;

		case 'a':
		outmode |= OM_MAC_AP;
		break;

		case 'A':
		outmode |= OM_NONCE_AP;
		break;

		case 's':
		outmode |= OM_MAC_STA;
		break;

		case 'S':
		outmode |= OM_NONCE_STA;
		break;

		case 'M':
		outmode |= OM_KEYMIC;
		break;

		case 'R':
		outmode |= OM_REPLAYCOUNT;
		break;

		case 'w':
		outmode |= OM_KEYVER;
		break;

		case 'P':
		outmode |= OM_KEYTYPE;
		break;

		case 'p':
		outmode |= OM_MESSAGE_PAIR;
		break;

		case 'r':
		outmode |= OM_REPLAYCOUNT;
		break;

		case 'l':
		outmode |= OM_ESSID_LEN;
		break;

		case 'e':
		outmode |= OM_ESSID;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

globalinit();
if(hcxinname != NULL)
	hcxorgrecords = readhccapx(hcxinname);

if(johninname != NULL)
	hcxorgrecords = readjohn(johninname);


if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

writehcxinfo(hcxorgrecords, outmode);

if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

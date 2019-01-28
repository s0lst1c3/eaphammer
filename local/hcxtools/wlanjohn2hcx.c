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

static char *hcxoutname = NULL;
static char *essidoutname = NULL;

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
static bool checkessid(uint8_t essid_len, char *essid)
{
int p;

if(essid_len == 0)
	return false;

if(essid_len > 32)
	return false;

for(p = 0; p < essid_len; p++)
	if ((essid[p] < 0x20) || (essid[p] > 0x7e))
		return false;
return true;
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
static bool processhc(hccap_t *zeiger)
{
FILE *fhhcx = NULL;
FILE *fhessid = NULL;
int essid_len;
uint8_t m;
hcx_t hcxrecord;

char essidout[36];

memset(&essidout, 0, 36);
memcpy(&essidout, zeiger->essid, 36);
essid_len = strlen(essidout);
if((essid_len == 0) || (essid_len > 32) || (zeiger->essid[0] == 0))
	return false;

m = geteapkey(zeiger->eapol);
if((m < 2) || (m > 4))
	return false;

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", hcxoutname);
		return false;
		}
	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		fclose(fhhcx);
		return false;
		}
	}

if(fhessid != NULL)
	{
	if(checkessid(essid_len, essidout) == true)
		fprintf(fhessid, "%s\n", essidout);
	}

if(fhhcx != 0)
	{
	memset(&hcxrecord, 0, HCX_SIZE);
	hcxrecord.signature = HCCAPX_SIGNATURE;
	hcxrecord.version = HCCAPX_VERSION;
	hcxrecord.essid_len = essid_len;
	if(m == 2)
		hcxrecord.message_pair = MESSAGE_PAIR_M12E2NR;
	if(m == 3)
		hcxrecord.message_pair = MESSAGE_PAIR_M32E3NR;
	if(m == 4)
		hcxrecord.message_pair = MESSAGE_PAIR_M14E4NR;
	memcpy(hcxrecord.essid, zeiger->essid, essid_len);
	hcxrecord.keyver = geteapkeyver(zeiger->eapol);
	memcpy(hcxrecord.mac_ap.addr, zeiger->mac1, 6);
	memcpy(hcxrecord.nonce_ap, zeiger->nonce2, 32);
	memcpy(hcxrecord.mac_sta.addr, zeiger->mac2, 6);
	memcpy(hcxrecord.nonce_sta, zeiger->nonce1, 32);
	hcxrecord.eapol_len = zeiger->eapol_size;
	memcpy(hcxrecord.eapol, zeiger->eapol, 256);
	memcpy(hcxrecord.keymic, zeiger->keymic, 16);
	memset(&hcxrecord.eapol[0x51], 0, 16);
	fwrite(&hcxrecord, HCX_SIZE, 1,fhhcx);
	}

if(fhessid != NULL)
	fclose(fhessid);

if(fhhcx != 0)
	fclose(fhhcx);

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
static bool processjohn(char *johninname)
{
int len;
int l;
int le;
int i;
long int hcxcount = 0;
FILE *fhjohn;
uint8_t *hcptr = NULL;
hccap_t *hc = NULL;
char *ptr = NULL;
char *ptre = NULL;
char *ptressid = NULL;
const char *formatstring = "$WPAPSK$";

char linein[LINEBUFFER];

unsigned char hctemp[HCCAP_SIZE];


if((fhjohn = fopen(johninname, "r")) == NULL)
	{
	fprintf(stderr, "unable to open database %s\n", johninname);
	exit (EXIT_FAILURE);
	}

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
	if(processhc(hc) == true)
		hcxcount++;
	}
fclose(fhjohn);
printf("%ld record(s) written to %s\n", hcxcount, hcxoutname);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.john] [input.john] ...\n"
	"\n"
	"options:\n"
	"-o <file> : output hccapx file\n"
	"-e <file> : output ESSID list\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int index;
int auswahl;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:e:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'o':
		hcxoutname = optarg;
		break;

		case 'e':
		essidoutname = optarg;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

globalinit();
for (index = optind; index < argc; index++)
	{
	if(processjohn(argv[index]) == false)
		{
		fprintf(stderr, "error processing records from %s\n", (argv[index]));
		exit(EXIT_FAILURE);
		}
	}


return EXIT_SUCCESS;
}

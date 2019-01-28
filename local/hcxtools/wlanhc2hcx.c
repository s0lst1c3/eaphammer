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

struct hccap
{
  char essid[36];
  uint8_t mac1[6];	/* bssid */
  uint8_t mac2[6];	/* client */
  uint8_t nonce1[32];	/* snonce client */
  uint8_t nonce2[32];	/* anonce bssid */
  uint8_t eapol[256];
  int eapol_size;
  int keyver;
  uint8_t keymic[16];
};
typedef struct hccap hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))

/*===========================================================================*/
/* globale Variablen */

static long int eapolerror = 0;

static char *hcxoutname = NULL;
static char *essidoutname = NULL;
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
const eap_t *eap;
uint16_t keyinfo;
int eapkey = 0;

eap = (const eap_t*)(uint8_t*)(eapdata);
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
static long int processhc(long int hcsize, hccap_t *zeiger)
{
FILE *fhhcx = NULL;
FILE *fhessid = NULL;
long int p;
long int wc = 0;
int essid_len;
int c1;
uint8_t m;

hcx_t hcxrecord;

char essidout[36];

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", hcxoutname);
		return 0;
		}
	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		fclose(fhhcx);
		return 0;
		}
	}

for(p = 0; p < hcsize; p++)
	{
	memset(&essidout, 0, 36);
	memcpy(&essidout, zeiger->essid, 32);
	essid_len = strlen(essidout);
	if((essid_len == 0) || (essid_len > 32) || (zeiger->essid[0] == 0))
		{
		zeiger++;
		continue;
		}

	if(fhessid != NULL)
		{
		if(checkessid(essid_len, essidout) == true)
			fprintf(fhessid, "%s\n", essidout);
		else
			{
			fprintf(fhessid, "$HEX[");
			for(c1 = 0; c1 < essid_len; c1++)
				fprintf(fhessid, "%02x", essidout[c1]);
			fprintf(fhessid, "]\n");
			}
		}

	if(fhhcx != 0)
		{
		memset(&hcxrecord, 0, HCX_SIZE);
		hcxrecord.signature = HCCAPX_SIGNATURE;
		hcxrecord.version = HCCAPX_VERSION;
		m = geteapkey(zeiger->eapol);
		if(m == 2)
			hcxrecord.message_pair = MESSAGE_PAIR_M12E2NR;
		else if(m == 3)
			hcxrecord.message_pair = MESSAGE_PAIR_M32E3NR;
		else if(m == 4)
			hcxrecord.message_pair = MESSAGE_PAIR_M14E4NR;
		else
			{
			zeiger++;
			eapolerror++;
			continue;
			}
		hcxrecord.essid_len = essid_len;
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
		wc++;
		}
	zeiger++;
	}

if(fhessid != NULL)
	fclose(fhessid);

if(fhhcx != 0)
	fclose(fhhcx);

return wc ;
}
/*===========================================================================*/
static long int processhcx(long int hcxsize, hcx_t *zeiger)
{
FILE *fhhcx = NULL;
FILE *fhessid = NULL;
long int p;
long int wc = 0;
int c1;
uint8_t m;
char essidout[36];

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", hcxoutname);
		return 0;
		}
	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		fclose(fhhcx);
		return 0;
		}
	}

for(p = 0; p < hcxsize; p++)
	{
	if(zeiger->signature == HCCAPX_SIGNATURE)
		{
		if((zeiger->essid_len == 0) || (zeiger->essid_len > 32) || (zeiger->essid[0] == 0))
			{
			zeiger++;
			continue;
			}

		if(fhessid != NULL)
			{
			memset(&essidout, 0, 36);
			memcpy(&essidout, zeiger->essid, zeiger->essid_len);
			if(checkessid(zeiger->essid_len, essidout) == true)
				fprintf(fhessid, "%s\n", essidout);
			else
				{
				fprintf(fhessid, "$HEX[");
				for(c1 = 0; c1 < zeiger->essid_len; c1++)
					fprintf(fhessid, "%02x", essidout[c1]);
				fprintf(fhessid, "]\n");
				}
			}

		if(fhhcx != 0)
			{
			m = geteapkey(zeiger->eapol);
			if(m == 2)
				zeiger->message_pair = MESSAGE_PAIR_M12E2;
			else if(m == 3)
				zeiger->message_pair = MESSAGE_PAIR_M32E3;
			else if(m == 4)
				zeiger->message_pair = MESSAGE_PAIR_M14E4;
			else
				{
				eapolerror++;
				zeiger++;
				continue;
				}
			zeiger->keyver = geteapkeyver(zeiger->eapol);
			fwrite(zeiger, HCX_SIZE, 1,fhhcx);
			wc++;
			}
		}
	zeiger++;
	}

if(fhessid != NULL)
	fclose(fhessid);

if(fhhcx != 0)
	fclose(fhhcx);

return wc;
}
/*===========================================================================*/
static bool processdata(char *hcinname)
{
struct stat statinfo;
FILE *fhhc;
uint8_t *data = NULL;
hcx_t *zeigerhcx = NULL;
hccap_t *zeigerhc = NULL;
long int datasize = 0;
long int hcxsize = 0;
long int hcsize = 0;
long int writecounter = 0;

eapolerror = 0;
if(hcinname == NULL)
	return false;

if(stat(hcinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcinname);
	return false;
	}

if((fhhc = fopen(hcinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s\n", hcinname);
	return false;
	}

data = malloc(statinfo.st_size);
if(data == NULL)
	{
	fprintf(stderr, "out of memory to store hc data\n");
	fclose(fhhc);
	return false;
	}


datasize = fread(data, 1, statinfo.st_size, fhhc);
fclose(fhhc);
if(datasize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hc file %s\n", hcinname);
	free(data);
	return false;
	}

hcxsize = datasize / HCX_SIZE;
hcsize = datasize / HCCAP_SIZE;


zeigerhcx = (hcx_t*)(data);
zeigerhc = (hccap_t*)(data);
if(((datasize % HCX_SIZE) == 0) && (zeigerhcx->signature == HCCAPX_SIGNATURE))
	{
	printf("%ld record(s) read from %s\n", hcxsize, hcinname);
	writecounter = processhcx(hcxsize, zeigerhcx);
	}

else if((datasize % HCCAP_SIZE) == 0)
	{
	printf("%ld record(s) read from %s\n", hcsize, hcinname);
	writecounter = processhc(hcsize, zeigerhc);
	}
else
	printf("invalid file size %s\n", hcinname);


free(data);
if(eapolerror > 0)
	printf("\x1B[31m%ld record(s) ignored (wrong eapolsize)\x1B[0m\n", eapolerror);
if(writecounter > 0)
	printf("%ld record(s) written to %s\n", hcsize, hcxoutname);


return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.hccap(x)] [input.hccap(x)] ...\n"
	"       %s <options> *.cap\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-o <file> : output hccapx file\n"
	"-e <file> : output ESSID list\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname);
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

for (index = optind; index < argc; index++)
	{
	if(hcxoutname != NULL)
		if(strcmp(argv[index], hcxoutname) == 0)
			{
			fprintf(stderr, "\x1B[31mfile skipped (inputname = outputname) %s\x1B[0m\n", (argv[index]));
			continue;
			}
	if(processdata(argv[index]) == false)
		{
		fprintf(stderr, "error processing records from %s\n", (argv[index]));
		exit(EXIT_FAILURE);
		}
	}


return EXIT_SUCCESS;
}

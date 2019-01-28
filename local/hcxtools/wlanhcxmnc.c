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

/*===========================================================================*/
/* globale Variablen */

static hcx_t *hcxdata = NULL;
/*===========================================================================*/
static void printhex(const uint8_t *buffer, int size)
{
int c;
for (c = 0; c < size; c++)
	fprintf(stdout, "%02x", buffer[c]);
return;
}
/*===========================================================================*/
static bool checknonce(uint8_t *nonce, uint8_t *eapdata)
{
const eap_t *eap;
eap = (const eap_t*)(uint8_t*)(eapdata);

if(memcmp(nonce, eap->nonce, 32) == 0)
	return true;
return false;
}
/*===========================================================================*/
static int sort_by_data_ap(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) < 0)
	return -1;

if(memcmp(ia->nonce_ap, ib->nonce_ap, 32) > 0)
	return 1;
else if (memcmp(ia->nonce_ap, ib->nonce_ap, 32) < 0)
	return -1;

return 0;
}
/*===========================================================================*/
static void getapinfo(long int hcxrecords)
{
int c;
hcx_t *zeigerhcx;

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_data_ap);

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(checknonce(zeigerhcx->nonce_ap, zeigerhcx->eapol) == false)
		{
		printhex(zeigerhcx->mac_ap.addr, 6);
		fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_ap, 32);
		fprintf(stdout, "\n");
		}
	c++;
	}
return;
}
/*===========================================================================*/
static void dononcecorr(long int hcxrecords, unsigned long long int mac_ap, int nb, int nc, char *hcxoutname)
{
int v;
long int c;
long int rw = 0;
hcx_t *zeigerhcx;
adr_t mac;
FILE *fhhcx;

mac.addr[5] = mac_ap & 0xff;
mac.addr[4] = (mac_ap >> 8) & 0xff;
mac.addr[3] = (mac_ap >> 16) & 0xff;
mac.addr[2] = (mac_ap >> 24) & 0xff;
mac.addr[1] = (mac_ap >> 32) & 0xff;
mac.addr[0] = (mac_ap >> 40) & 0xff;

if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxoutname);
	return;
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 6) == 0)
		{
		if(checknonce(zeigerhcx->nonce_ap, zeigerhcx->eapol) == false)
			{
			for(v = 0; v <= nc; v++)
				{
				zeigerhcx->nonce_ap[nb] = (zeigerhcx->nonce_ap[nb] +1) &0xff;
				fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
				rw++;
				}
			}
		}

	c++;
	}
fclose(fhhcx);
printf("%ld records written\n", rw);
return;
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
	"-i <file>   : input hccapx file\n"
	"-o <file>   : input hccapx file\n"
	"-a <xdigit> : mac_ap to correct\n"
	"-b <digit>  : nonce byte to correct\n"
	"-n <xdigit> : nonce hex value\n"
	"-I          : show mac_ap and anonces\n"
	"-h          : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int modus = 0;
int nc = 0;
int nb = 0;
int malen = 0;
long int hcxorgrecords = 0;
unsigned long long int mac_ap = 0xffffffffffffL;

char *hcxinname = NULL;
char *hcxoutname = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:a:b:n:Ivh")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'o':
		hcxoutname = optarg;
		break;

		case 'b':
		nb = strtoul(optarg, NULL, 10);
		if((nb < 0) || (nb > 31))
			{
			fprintf(stderr, "error wrong value (only 0 > 31 allowed)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'a':
		malen = strlen(optarg);
		if(malen > 12)
			{
			fprintf(stderr, "error wrong mac_ap size (only 12 xdigit allowed: 112233aabbcc)\n");
			exit(EXIT_FAILURE);
			}

		mac_ap = strtoul(optarg, NULL, 16);
		break;

		case 'n':
		nc = strtoul(optarg, NULL, 16) & 0xff;
		if((nc < 0) || (nc > 0xff))
			{
			fprintf(stderr, "error wrong value (only 0 > 0xff allowed)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'I':
		modus = 'I';
		break;

		default:
		usage(basename(argv[0]));
		}
	}

if(hcxinname == NULL)
	{
	fprintf(stderr, "no inputfile selected\n");
	exit(EXIT_FAILURE);
	}


hcxorgrecords = readhccapx(hcxinname);
if(hcxorgrecords == 0)
	return EXIT_SUCCESS;

if(modus == 'I')
	{
	getapinfo(hcxorgrecords);
	if(hcxdata != NULL)
	free(hcxdata);
	return EXIT_SUCCESS;
	}

if(hcxoutname == NULL)
	{
	fprintf(stderr, "no outputfile selected\n");
	exit(EXIT_FAILURE);
	}

dononcecorr(hcxorgrecords, mac_ap, nb, nc, hcxoutname);


if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

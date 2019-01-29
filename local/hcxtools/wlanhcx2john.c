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

static char *johnoutname = NULL;
/*===========================================================================*/
static void hccap2base(FILE *fhjohn, unsigned char *in, unsigned char b)
{
char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fprintf(fhjohn, "%c", (itoa64[in[0] >> 2]));
fprintf(fhjohn, "%c", (itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]));
if (b)
	{
	fprintf(fhjohn, "%c", (itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]));
	fprintf(fhjohn, "%c", (itoa64[in[2] & 0x3f]));
	}
else
	fprintf(fhjohn, "%c", (itoa64[((in[1] & 0x0f) << 2)]));
return;
}
/*===========================================================================*/
static void mac2asciilong(char ssid[18], unsigned char *p)
{
sprintf(ssid, "%02x-%02x-%02x-%02x-%02x-%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
static void mac2ascii(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x%02x%02x%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
static void writejohn(FILE *fhjohn, hccap_t * hc, const char *basename, uint8_t message_pair)
{
unsigned int i;
unsigned char *hcpos = (unsigned char *)hc;
char sta_mac[18];
char ap_mac[18];
char ap_mac_long[13];

mac2ascii(ap_mac_long, hc->mac1);
mac2asciilong(ap_mac, hc->mac1);
mac2asciilong(sta_mac, hc->mac2);

fprintf(fhjohn, "%s:$WPAPSK$%s#", hc->essid, hc->essid);
for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
	hccap2base(fhjohn, &hcpos[i], 1);
hccap2base(fhjohn, &hcpos[i], 0);
fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
if (hc->keyver > 1)
	fprintf(fhjohn, "%d", hc->keyver);

if((message_pair &0x80) > 1)
	fprintf(fhjohn, ":verified:%s\n", basename);
else
	fprintf(fhjohn, ":not verified:%s\n", basename);
return;
}
/*===========================================================================*/
static void processhcx(long int hcxsize, hcx_t *zeiger, char *hcxinname)
{
FILE *fhjohn = NULL;
long int p;
long int errorcount = 0;
long int johncount = 0;
char *hcxinbasename = hcxinname;

hccap_t hcdata;

if(johnoutname != NULL)
	{
	if((fhjohn = fopen(johnoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", johnoutname);
		return;
		}
	}

for(p = 0; p < hcxsize; p++)
	{
	if(zeiger->signature == HCCAPX_SIGNATURE)
		{
		if(zeiger->essid_len > 32)
			{
			errorcount++;
			zeiger++;
			continue;
			}

		if(fhjohn != 0)
			{
			memset(&hcdata, 0, HCCAP_SIZE);
			memcpy(&hcdata.essid, zeiger->essid, zeiger->essid_len);
			memcpy(&hcdata.mac1, zeiger->mac_ap.addr, 6);
			memcpy(&hcdata.mac2, zeiger->mac_sta.addr, 6);
			memcpy(&hcdata.nonce1, zeiger->nonce_sta, 32);
			memcpy(&hcdata.nonce2, zeiger->nonce_ap, 32);
			memcpy(&hcdata.eapol, zeiger->eapol, 256);
			hcdata.eapol_size = zeiger->eapol_len;
			hcdata.keyver = zeiger->keyver;
			memcpy(&hcdata.keymic, zeiger->keymic, 16);
			if ((hcxinbasename = strrchr(hcxinname, '/')))
				hcxinname = ++hcxinbasename;
			writejohn(fhjohn, &hcdata, hcxinname, zeiger->message_pair);
			johncount++;
			}
		}
	zeiger++;
	}
if(fhjohn != 0)
	fclose(fhjohn);

if(errorcount == 1)
	printf("%ld error detected\n", errorcount);

else if(errorcount > 1)
	printf("%ld errors detected\n", errorcount);


if(johncount == 1)
	printf("%ld record written to %s\n", johncount, johnoutname);

else if(johncount > 1)
	printf("%ld records written to %s\n", johncount, johnoutname);

return;
}
/*===========================================================================*/
static bool processdata(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
uint8_t *data = NULL;
hcx_t *zeigerhcx = NULL;
long int datasize = 0;
long int hcxsize = 0;

if(hcxinname == NULL)
	return false;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return false;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s\n", hcxinname);
	return false;
	}

data = malloc(statinfo.st_size);
if(data == NULL)
	{
	fprintf(stderr, "out of memory to store hc data\n");
	fclose(fhhcx);
	return false;
	}


datasize = fread(data, 1, statinfo.st_size, fhhcx);
fclose(fhhcx);
if(datasize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hc file %s\n", hcxinname);
	free(data);
	return false;
	}

hcxsize = datasize / HCX_SIZE;
zeigerhcx = (hcx_t*)(data);
if(((datasize % HCX_SIZE) == 0) && (zeigerhcx->signature == HCCAPX_SIGNATURE))
	{
	printf("%ld records read from %s\n", hcxsize, hcxinname);
	processhcx(hcxsize, zeigerhcx, hcxinname);
	}

free(data);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.hccapx] [input.hccapx] ...\n"
	"\n"
	"options:\n"
	"-o <file> : output john file\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int index;
int auswahl;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'o':
		johnoutname = optarg;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

for (index = optind; index < argc; index++)
	{
	if(processdata(argv[index]) == false)
		{
		fprintf(stderr, "error processing records from %s\n", (argv[index]));
		exit(EXIT_FAILURE);
		}
	}


return EXIT_SUCCESS;
}

#define _GNU_SOURCE
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxpsktool.h"
#include "include/hashcatops.h"
#include "include/strings.c"

/*===========================================================================*/
/* global var */

apessidl_t *apessidliste;
int apessidcount;
int thisyear;
/*===========================================================================*/
/*===========================================================================*/
static void writepsk(FILE *fhout, const char *pskstring)
{
bool lflag = false;
bool uflag = false;
int p, l;
char lowerpskstring[PSKSTRING_LEN_MAX] = {};
char upperpskstring[PSKSTRING_LEN_MAX] = {};

l = strlen(pskstring);
if((l < 8) || (l > PSKSTRING_LEN_MAX))
	{
	return;
	}
for(p = 0; p < l; p++)
	{
	if(islower(pskstring[p]))
		{
		upperpskstring[p] = toupper(pskstring[p]);
		uflag = true;
		}
	else
		{
		upperpskstring[p] = pskstring[p];
		}

	if(isupper(pskstring[p]))
		{
		lowerpskstring[p] = tolower(pskstring[p]);
		lflag = true;
		}
	else
		{
		lowerpskstring[p] = pskstring[p];
		}
	}

fprintf(fhout,"%s\n", pskstring);
if(uflag == true)
	fprintf(fhout,"%s\n", upperpskstring);
if(lflag == true)
	fprintf(fhout,"%s\n", lowerpskstring);
return;
}
/*===========================================================================*/
static void writeessidadd(FILE *fhout, char *essid)
{
int c;
static char essidstring[PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX] = {};

for(c = 1900; c <= thisyear; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%04d%s", c, essid);
	writepsk(fhout, essidstring);
	}

for(c = 0; c < 1000; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%d%s", c, essid);
	writepsk(fhout, essidstring);
	}
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s123456789", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s12345678", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234567", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s123456", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s12345", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@Home", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@WiFi", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@1234", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@123", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s!", essid);
writepsk(fhout, essidstring);
return;
}
/*===========================================================================*/
static bool writeessidremoved(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int pi;
static int po;
static int essidlentmp;
static bool removeflag;

static char essidtmp[PSKSTRING_LEN_MAX] = {};

po = 0;
removeflag = false;
essidlentmp = essidlen;
memset(&essidtmp, 0, PSKSTRING_LEN_MAX);
for(pi = 0; pi < essidlen; pi++)
	{
	if(((essid[pi] >= 'A') && (essid[pi] <= 'Z')) || ((essid[pi] >= 'a') && (essid[pi] <= 'z')))
		{
		essidtmp[po] = essid[pi];
		po++;
		}
	else
		{
		essidlentmp--;
		removeflag = true;
		}
	}
if(removeflag == false)
	{
	writeessidadd(fhout, essidtmp);
	}
return removeflag;
}
/*===========================================================================*/
static void writeessidsweeped(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int l1, l2;
static uint8_t sweepstring[PSKSTRING_LEN_MAX] = {};

for(l1 = 3; l1 <= essidlen; l1++)
	{
	for(l2 = 0; l2 <= essidlen -l1; l2++)
		{
		memset(&sweepstring, 0, PSKSTRING_LEN_MAX);
		memcpy(&sweepstring, &essid[l2], l1);
		if(writeessidremoved(fhout, l1, sweepstring) == false)
			{
			writepsk(fhout, (char*)sweepstring);
			}
		}
	}
return;
}
/*===========================================================================*/
static void prepareessid(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int pi, po;
writeessidsweeped(fhout, essidlen, essid);

static char essidtmp[PSKSTRING_LEN_MAX] = {};

po = 0;
memset(&essidtmp, 0, PSKSTRING_LEN_MAX);
for(pi = essidlen -1; pi >= 0; pi--)
	{
	essidtmp[po] = essid[pi];
	po++;
	}
writepsk(fhout, essidtmp);
return;
}
/*===========================================================================*/
static void processessids(FILE *fhout)
{
static int c;
static apessidl_t *zeiger;
static apessidl_t *zeiger1;

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_essid);
zeiger = apessidliste;
for(c = 0; c < apessidcount; c++)
	{
	if(c == 0)
		{
		prepareessid(fhout, zeiger->essidlen, zeiger->essid);
		}
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->essidlen != zeiger1->essidlen)
			{
			if(memcmp(zeiger->essid, zeiger1->essid, zeiger->essidlen) != 0)
				{
				prepareessid(fhout, zeiger->essidlen, zeiger->essid);
				}
			}
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writebssidmd5(FILE *fhout, unsigned long long int macaddr)
{
MD5_CTX ctxmd5;
int k;
int p;
char keystring[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char macstring[PSKSTRING_LEN_MAX] = {};
unsigned char digestmd5[MD5_DIGEST_LENGTH];

snprintf(macstring, 14, "%012llX", macaddr);
MD5_Init(&ctxmd5);
MD5_Update(&ctxmd5, macstring, 12);
MD5_Final(digestmd5, &ctxmd5);

for (p = 0; p < 10; p++)
	{
	fprintf(fhout, "%02x",digestmd5[p]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 8; p++)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 10; p++)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 15 ; p +=2)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 1; p < 16 ; p +=2)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");
return;
}
/*===========================================================================*/
static unsigned int wpspinchecksum(unsigned int pin)
{
static int accum = 0;

while (pin)
	{
	accum += 3 * (pin % 10);
	pin /= 10;
	accum += pin % 10;
	pin /= 10;
	}
return (10 - accum % 10) % 10;
}
/*---------------------------------------------------------------------------*/
static void writebssidwps(FILE *fhout, unsigned long long int macaddr)
{
static int pin;

pin = (macaddr & 0xffffff) % 10000000;
pin = ((pin * 10) + wpspinchecksum(pin));
fprintf(fhout, "%08d \n", pin);
return;
}
/*===========================================================================*/
static void writebssid(FILE *fhout, unsigned long long int macaddr)
{
char pskstring[PSKSTRING_LEN_MAX] = {};

snprintf(pskstring, PSKSTRING_LEN_MAX, "%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%011llx", macaddr &0xfffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%010llx", macaddr &0xffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%09llx", macaddr &0xfffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%08llx", macaddr &0xffffffff);
writepsk(fhout, pskstring);
writebssidmd5(fhout, macaddr);
writebssidwps(fhout, macaddr);
return;
}
/*===========================================================================*/
static void preparebssid(FILE *fhout, unsigned long long int macaddr)
{
int c;
unsigned long long int oui;
unsigned long long int nic;

oui = macaddr &0xffffff000000L;
nic = (macaddr &0xffffffL) -8;
for(c = 0; c < 0x10; c++)
	{
	writebssid(fhout, oui +nic +c);
	}




return;
}
/*===========================================================================*/
static void processbssids(FILE *fhout)
{
static int c;
static apessidl_t *zeiger;
static apessidl_t *zeiger1;

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_ap);
zeiger = apessidliste;
for(c = 0; c < apessidcount; c++)
	{
	if(c == 0)
		{
		preparebssid(fhout, zeiger->macaddr);
		}
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->macaddr != zeiger1->macaddr)
			{
			preparebssid(fhout, zeiger->macaddr);
			}
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void addapessid(uint64_t macaddr, uint8_t essidlen, uint8_t *essid)
{
static apessidl_t *zeiger;

if(essidlen > ESSID_LEN_MAX)
	{
	return;
	}
if(apessidliste == NULL)
	{
	apessidliste = malloc(APESSIDLIST_SIZE);
	if(apessidliste == NULL)
		{
		fprintf(stderr, "failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(apessidliste, 0, APESSIDLIST_SIZE);
	apessidliste->macaddr = macaddr;
	apessidliste->essidlen = essidlen;
	memcpy(apessidliste->essid, essid, essidlen);
	apessidcount++;
	return;
	}
zeiger = apessidliste +apessidcount -1;
if((zeiger->macaddr == macaddr) && (zeiger->essidlen == essidlen) && (memcmp(zeiger->essid, essid, essidlen) == 0))
	{
	return;
	}
zeiger = realloc(apessidliste, (apessidcount +1) *APESSIDLIST_SIZE);
if(zeiger == NULL)
	{
	fprintf(stderr, "failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
apessidliste = zeiger;
zeiger = apessidliste +apessidcount;
memset(zeiger, 0, APESSIDLIST_SIZE);
zeiger->macaddr = macaddr;
zeiger->essidlen = essidlen;
memcpy(zeiger->essid, essid, essidlen);
apessidcount++;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream))
	return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static inline void readpmkidfile(char *pmkidname)
{
static int len;
static int aktread = 1;
static int essidlen;
static char *macaddrstop = NULL;
static unsigned long long int macaddr;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];
static uint8_t essid[ESSID_LEN_MAX];

if((fh_file = fopen(pmkidname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", pmkidname);
	return;
	}

while(1)
	{
	if((len = fgetline(fh_file, PMKID_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((linein[32] != '*') && (linein[45] != '*') && (linein[58] != '*'))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidlen = len -59;
	if((essidlen %2) != 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	macaddr = strtoull(linein +33, &macaddrstop, 16);
	if((macaddrstop -linein) != 45)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(hex2bin(&linein[59], essid, essidlen/2) == true)
		{
		addapessid(macaddr, essidlen/2, essid);
		}
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static inline void readhccapxfile(char *hccapxname)
{
static struct stat statinfo;
static hccapx_t *hcxptr;
static FILE *fhhcx;
static unsigned long long int macaddr;

static uint8_t hcxdata[HCCAPX_SIZE];

if(stat(hccapxname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapxname);
	return;
	}

if((statinfo.st_size %HCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return;
	}

if((fhhcx = fopen(hccapxname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxname);
	return;
	}

hcxptr = (hccapx_t*)hcxdata;
while(fread(&hcxdata, HCCAPX_SIZE, 1, fhhcx) == 1)
	{
	if(hcxptr->signature != HCCAPX_SIGNATURE)
		{
		continue;
		}
	if((hcxptr->version != 3) && (hcxptr->version != 4))
		{
		continue;
		}
	if(hcxptr->essid_len > ESSID_LEN_MAX)
		{
		continue;
		}
	macaddr = 0;
	macaddr = hcxptr->mac_ap[0];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[1];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[2];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[3];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[4];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[5];
	addapessid(macaddr, hcxptr->essid_len, hcxptr->essid);
	}
fclose(fhhcx);
return;
}
/*===========================================================================*/
static inline void readcommandline(char *macapname, char *essidname)
{
static int essidlen = 0;
static int essidlenuh = 0;
static char *macaddrstop = NULL;
static unsigned long long int macaddr = 0xffffffffffffL;
static uint8_t essid[ESSID_LEN_MAX];

if(macapname != NULL)
	{
	macaddr = strtoull(macapname, &macaddrstop, 16);
	if((macaddrstop -macapname) != 12)
			{
			fprintf(stderr, "invalid MAC specified\n");
			}
	}

memset(&essid, 0, ESSID_LEN_MAX);
essidlen = strlen(essidname);
if(essidname != NULL)
	{
	essidlenuh = ishexify(essidname);
	if((essidlenuh > 0) && (essidlenuh <= ESSID_LEN_MAX))
		{
		if(hex2bin(&essidname[5], essid, essidlenuh) == true)
			{
			addapessid(macaddr, essidlenuh, essid);
			}
		return;
		}
	memset(&essid, 0, ESSID_LEN_MAX);
	if(essidlen <= ESSID_LEN_MAX)
		{
		memcpy(&essid, essidname, essidlen);
		}
	}
addapessid(macaddr, essidlen, essid);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input EAPOL hash file (hccapx)\n"
	"-z <file> : input PMKID hash file\n"
	"-e <file> : input ESSID\n"
	"-b <file> : input MAC access point\n"
	"            format: 112233445566\n"
	"-o <file> : output PSK file\n"
	"            default: stdout\n"
	"            output list must be sorted unique!\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static FILE *fhpsk;
static time_t t;
static struct tm *tm;

static char *hccapxname = NULL;
static char *pmkidname = NULL;
static char *essidname = NULL;
static char *macapname = NULL;
static char *pskname = NULL;

apessidliste = NULL;
apessidcount = 0;

static const char *short_options = "i:z:o:e:b:o:hv";
static const struct option long_options[] =
{
	{"version",			no_argument,		NULL,	HCXD_VERSION},
	{"help",			no_argument,		NULL,	HCXD_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{

		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

optind = 1;
optopt = 0;
index = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case 'h':
		usage(basename(argv[0]));
		break;

		case 'i':
		hccapxname = optarg;
		break;

		case 'z':
		pmkidname = optarg;
		break;

		case 'e':
		essidname = optarg;
		break;

		case 'b':
		macapname = optarg;
		if(strlen(macapname) != 12)
			{
			fprintf(stderr, "invalid MAC specified\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		pskname = optarg;
		break;

		case 'v':
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

t = time(NULL);
tm = localtime(&t);
thisyear = tm->tm_year +1900;

if((macapname != NULL) || (essidname != NULL))
	{
	readcommandline(macapname, essidname);
	}

if(pmkidname != NULL)
	{
	readpmkidfile(pmkidname);
	}

if(hccapxname != NULL)
	{
	readhccapxfile(hccapxname);
	}

if(apessidliste == NULL)
	{
	fprintf(stderr, "no hashes loaded\n");
	exit(EXIT_FAILURE);
	}

if(pskname != NULL)
	{
	if((fhpsk = fopen(pskname, "w")) == NULL)
		{
		fprintf(stderr, "1 error opening psk file %s\n", pskname);
		exit(EXIT_FAILURE);
		}
	processbssids(fhpsk);
	processessids(fhpsk);
	}
else
	{
	processbssids(stdout);
	processessids(stdout);
	}

if(pskname != NULL)
	{
	fclose(fhpsk);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

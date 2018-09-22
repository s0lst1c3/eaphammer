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
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#include <endian.h>
#endif
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

#include "include/version.h"
#include "common.c"
#include "com_md5_64.c"
#include "com_aes.c"
#include "com_formats.c"


static bool hex2bin(const char *str, uint8_t *bytes, size_t blen);

/*===========================================================================*/
/* globale Variablen */

static hcx_t *hcxdata;
static FILE *fhpot;
/*===========================================================================*/
__attribute__ ((nonnull(2)))
static void hcxpmk(long int hcxrecords, char *pmkname)
{
int p;

long int c;
hcx_t *zeigerhcx;

uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

char outstr[1024];


if(hex2bin(pmkname, pmkin, 32) != true)
	{
	fprintf(stderr, "error wrong plainmasterkey value (allowed: 64 xdigits)\n");
	exit(EXIT_FAILURE);
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memset(&pkedata, 0, sizeof(mic));
	memcpy(&pmk, &pmkin, 32);
	if(zeigerhcx->keyver == 1)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_md5(), &ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}

	else if(zeigerhcx->keyver == 2)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}

	else if(zeigerhcx->keyver == 3)
		{
		generatepkeprf(zeigerhcx, pkedata);
		pkedata_prf[0] = 1;
		pkedata_prf[1] = 0;
		memcpy (pkedata_prf + 2, pkedata, 98);
		pkedata_prf[100] = 0x80;
		pkedata_prf[101] = 1;
		HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
		omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}
	c++;
	}
return;
}
/*===========================================================================*/
static void hcxessidpmk(long int hcxrecords, char *essidname, int essidlen, char *pmkname)
{
int p;

long int c;
hcx_t *zeigerhcx;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

unsigned char essid[32];

char outstr[1024];


if(hex2bin(pmkname, pmkin, 32) != true)
	{
	fprintf(stderr, "error wrong plainmasterkey value (allowed: 64 xdigits)\n");
	exit(EXIT_FAILURE);
	}

memset(&essid, 0, 32);
memcpy(&essid, essidname, essidlen);

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&essid, zeigerhcx->essid, 32) == 0)
		{
		memset(&pkedata, 0, sizeof(pkedata));
		memset(&pkedata_prf, 0, sizeof(pkedata_prf));
		memset(&ptk, 0, sizeof(ptk));
		memset(&pkedata, 0, sizeof(mic));
		memcpy(&pmk, &pmkin, 32);
		if(zeigerhcx->keyver == 1)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}

		else if(zeigerhcx->keyver == 2)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}

		else if(zeigerhcx->keyver == 3)
			{
			generatepkeprf(zeigerhcx, pkedata);
			pkedata_prf[0] = 1;
			pkedata_prf[1] = 0;
			memcpy (pkedata_prf + 2, pkedata, 98);
			pkedata_prf[100] = 0x80;
			pkedata_prf[101] = 1;
			HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
			omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)pmkname, 64, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}
		}
	c++;
	}
return;
}
/*===========================================================================*/
static void hcxpassword(long int hcxrecords, char *passwordname, int passwordlen)
{
int p;
long int c;
hcx_t *zeigerhcx;
hcx_t *zeigerhcx2;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

char outstr[1024];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memset(&pkedata, 0, sizeof(mic));
	memcpy(&pmk, &pmkin, 32);
	memset(&mic, 0, 16);
	if(c > 0)
		{
		zeigerhcx2 = hcxdata +c -1;
		if(memcmp(zeigerhcx->essid, zeigerhcx2->essid, 32) != 0)
			{
			if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, zeigerhcx->essid, zeigerhcx->essid_len, 4096, EVP_sha1(), 32, pmkin) == 0)
				{
				fprintf(stderr, "could not generate plainmasterkey\n");
				return;
				}
			memcpy(&pmk, &pmkin, 32);
			}
		}
	else if(c == 0)
		{
		if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, zeigerhcx->essid, zeigerhcx->essid_len, 4096, EVP_sha1(), 32, pmkin) == 0)
			{
			fprintf(stderr, "could not generate plainmasterkey\n");
			return;
			}
		memcpy(&pmk, &pmkin, 32);
		}
	if(zeigerhcx->keyver == 1)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}

	else if(zeigerhcx->keyver == 2)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}

	else if(zeigerhcx->keyver == 3)
		{
		generatepkeprf(zeigerhcx, pkedata);
		pkedata_prf[0] = 1;
		pkedata_prf[1] = 0;
		memcpy (pkedata_prf + 2, pkedata, 98);
		pkedata_prf[100] = 0x80;
		pkedata_prf[101] = 1;
		HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
		omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			{
			showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
			if(fhpot != NULL)
				fprintf(fhpot, "%s\n",outstr);
			else
				printf("%s\n",outstr);
			}
		}

	c++;
	}
return;
}
/*===========================================================================*/
static void hcxessidpassword(long int hcxrecords, char *essidname, int essidlen, char *passwordname, int passwordlen)
{
int p;

long int c;
hcx_t *zeigerhcx;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

unsigned char essid[32] = { 0 };

char outstr[1024];

memcpy(&essid, essidname, essidlen);

if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, essid, essidlen, 4096, EVP_sha1(), 32, pmkin) == 0)
	{
	fprintf(stderr, "could not generate plainmasterkey\n");
	return;
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&essid, zeigerhcx->essid, 32) == 0)
		{
		memset(&pkedata, 0, sizeof(pkedata));
		memset(&pkedata_prf, 0, sizeof(pkedata_prf));
		memset(&ptk, 0, sizeof(ptk));
		memset(&pkedata, 0, sizeof(mic));
		memcpy(&pmk, &pmkin, 32);
		if(zeigerhcx->keyver == 1)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}

		else if(zeigerhcx->keyver == 2)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}

		else if(zeigerhcx->keyver == 3)
			{
			generatepkeprf(zeigerhcx, pkedata);
			pkedata_prf[0] = 1;
			pkedata_prf[1] = 0;
			memcpy (pkedata_prf + 2, pkedata, 98);
			pkedata_prf[100] = 0x80;
			pkedata_prf[101] = 1;
			HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
			omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
			if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
				{
				showhashrecord(zeigerhcx, (uint8_t*)passwordname, passwordlen, outstr);
				if(fhpot != NULL)
					fprintf(fhpot, "%s\n",outstr);
				else
					printf("%s\n",outstr);
				}
			}

		}
	c++;
	}
return;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
char *ptr = buffer +len -1;

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
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if(feof(inputstream))
	return -1;
char *buffptr = fgets (buffer, size, inputstream);

if(buffptr == NULL)
	return -1;

size_t len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static void hcxwordlist(long int hcxrecords, char *wordlistname)
{
int len;
int p;
FILE *fhpwin;

char linein[66];

if((fhpwin = fopen(wordlistname, "r")) == NULL)
	{
	fprintf(stderr, "error opening %s\n", wordlistname);
	return;
	}

while((len = fgetline(fhpwin, 66, linein)) != -1)
	{
	if(len < 8)
		continue;
	if(len == 64)
		{
		for(p = 0; p < 64; p++)
			if(!(isxdigit(linein[p])))
				continue;
		hcxpmk(hcxrecords, linein);
		continue;
		}
	if(len < 64)
		hcxpassword(hcxrecords, linein, len);
	}

fclose(fhpwin);
return;
}

/*===========================================================================*/
static void hcxessidwordlist(long int hcxrecords, char *essidname, int essidlen, char *wordlistname)
{
int len;
int p;
FILE *fhpwin;

char linein[66];

if((fhpwin = fopen(wordlistname, "r")) == NULL)
	{
	fprintf(stderr, "error opening %s\n", wordlistname);
	return;
	}

while((len = fgetline(fhpwin, 66, linein)) != -1)
	{
	if(len < 8)
		continue;
	if(len == 64)
		{
		for(p = 0; p < 64; p++)
			if(!(isxdigit(linein[p])))
				continue;
		hcxessidpmk(hcxrecords, essidname, essidlen, linein);
		continue;
		}
	if(len < 64)
		hcxessidpassword(hcxrecords, essidname, essidlen, linein, len);
	}

fclose(fhpwin);
return;
}
/*===========================================================================*/
static int sort_by_essid(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

return memcmp(ia->essid, ib->essid, 32);
}
/*===========================================================================*/
static long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return 0;

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

qsort(hcxdata, hcxsize / HCX_SIZE, sizeof(hcx_t), sort_by_essid);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
static bool hex2bin(const char *str, uint8_t *bytes, size_t blen)
{
size_t c;
uint8_t pos;
uint8_t idx0;
uint8_t idx1;

uint8_t hashmap[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

for(c = 0; c < blen; c++)
	{
	if(str[c] < '0')
		return false;
	if(str[c] > 'f')
		return false;
	if((str[c] > '9') && (str[c] < 'A'))
		return false;
	if((str[c] > 'F') && (str[c] < 'a'))
		return false;
	}

memset(bytes, 0, blen);
for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-w <file> : input wordlist, plainmasterkeylist oder mixed word-/plainmasterkeylist\n"
	"          : wordlist input is very slow\n"
	"-e        : input ESSID\n"
	"-p        : input password\n"
	"-P        : input plainmasterkey\n"
	"-o <file> : output recovered network data\n"
	"-h        : this help\n"
	"\n"
	"input option matrix\n"
	"-e and -p\n"
	"-e and -P\n"
	"-e and -w\n"
	"-p\n"
	"-P\n"
	"-w\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int p;
int essidlen = 0;
int passwordlen = 0;
int ret = 0;
long int hcxorgrecords = 0;
hcxdata = NULL;
fhpot = NULL;
struct stat statpot;
struct tm* tm_info;
struct timeval tv;

char *hcxinname = NULL;
char *essidname = NULL;
char *passwordname = NULL;
char *pmkname = NULL;
char *potname = NULL;
char *wordlistinname = NULL;

char zeitstring[26];

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:e:p:P:w:o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'e':
		essidname = optarg;
		essidlen = strlen(essidname);
		if((essidlen < 1) || (essidlen > 32))
			{
			fprintf(stderr, "error wrong essid len (allowed: 1 .. 32 characters)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'p':
		passwordname = optarg;
		passwordlen = strlen(passwordname);
		if((passwordlen < 8) || (passwordlen > 63))
			{
			fprintf(stderr, "error wrong password len (allowed: 8 .. 63 characters\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'P':
		pmkname = optarg;
		if(strlen(pmkname) != 64)
			{
			fprintf(stderr, "error wrong plainmasterkey len (allowed: 64 xdigits)\n");
			exit(EXIT_FAILURE);
			}
		for(p = 0; p < 64; p++)
			{
			if(!(isxdigit(pmkname[p])))
				{
				fprintf(stderr, "error wrong plainmasterkey len (allowed: 64 xdigits)\n");
				exit(EXIT_FAILURE);
				}
			}
		break;

		case 'o':
		potname = optarg;
		if((fhpot = fopen(potname, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", potname);
			exit(EXIT_FAILURE);
			}
		break;

		case 'w':
		wordlistinname = optarg;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

if((essidname == 0) && (passwordname != NULL) && (pmkname != NULL) && (wordlistinname != NULL))
	{
	fprintf(stderr, "nothing to do\n");
	return EXIT_SUCCESS;
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

gettimeofday(&tv, NULL);
tm_info = localtime(&tv.tv_sec);
strftime(zeitstring, 26, "%H:%M:%S", tm_info);
printf("started at %s to test %ld records\n", zeitstring, hcxorgrecords);

if((essidname != NULL) && (passwordname != NULL))
	hcxessidpassword(hcxorgrecords, essidname, essidlen, passwordname, passwordlen);

if((essidname != NULL) && (pmkname != NULL))
	hcxessidpmk(hcxorgrecords, essidname, essidlen, pmkname);

if((passwordname != NULL) && (essidname == NULL))
	hcxpassword(hcxorgrecords, passwordname, passwordlen);

if((pmkname != NULL) && (essidname == NULL))
	hcxpmk(hcxorgrecords, pmkname);

if((wordlistinname != NULL) && (essidname != NULL))
	hcxessidwordlist(hcxorgrecords, essidname, essidlen, wordlistinname);

if((wordlistinname != NULL) && (essidname == NULL))
	hcxwordlist(hcxorgrecords, wordlistinname);

gettimeofday(&tv, NULL);
tm_info = localtime(&tv.tv_sec);
strftime(zeitstring, 26, "%H:%M:%S", tm_info);
printf("finished at %s\n", zeitstring);


if(hcxdata != NULL)
	free(hcxdata);

if(fhpot != NULL)
	{
	fclose(fhpot);
	stat(potname, &statpot);
	if(statpot.st_size == 0)
		ret = remove(potname);
	if(ret != 0)
		fprintf(stderr, "could not remove empty file %s\n", potname);
	}

return EXIT_SUCCESS;
}

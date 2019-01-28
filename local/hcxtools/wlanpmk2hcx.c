#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <math.h>

#include "include/version.h"
#include "common.c"

/*===========================================================================*/
static void base64(const unsigned char* buffer, size_t length, char** b64text)
{
BIO *bio, *b64;
BUF_MEM *bufferPtr;

b64 = BIO_new(BIO_f_base64());
bio = BIO_new(BIO_s_mem());
bio = BIO_push(b64, bio);

BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
BIO_write(bio, buffer, length);
(void) BIO_flush(bio);
BIO_get_mem_ptr(bio, &bufferPtr);
(void) BIO_set_close(bio, BIO_NOCLOSE);
BIO_free_all(bio);
*b64text=(*bufferPtr).data;
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
static void outputhashlist(FILE *fhcombi, FILE *fhhash, FILE *fhjohn)
{
int c;
int combilen;
int essidlen;
long int hashcount = 0;
long int skippedcount = 0;
char *essidname = NULL;
char *hashrecord = NULL;
char combiline[100];
unsigned char pmkstr[64];
unsigned char essidstr[64];

while((combilen = fgetline(fhcombi, 100, combiline)) != -1)
	{
	if(combilen < 66)
		{
		skippedcount++;
		continue;
		}
	if(combiline[64] != ':')
		{
		skippedcount++;
		continue;
		}

	if(hexstr2bin(combiline, pmkstr, 64) != true)
		{
		skippedcount++;
		continue;
		}
	essidname = strchr(combiline, ':') +1;
	if(essidname == NULL)
		{
		skippedcount++;
		continue;
		}
	essidlen = strlen(essidname);
	if((essidlen < 1) || (essidlen > 32))
		{
		skippedcount++;
		continue;
		}

	if(fhhash != NULL)
		{
		memset(&essidstr, 0, 64);
		memcpy(&essidstr, essidname, essidlen);
		base64(essidstr, essidlen, &hashrecord);
		fprintf(fhhash, "sha1:4096:%s:", hashrecord);
		free(hashrecord);
		base64(pmkstr, 32, &hashrecord);
		fprintf(fhhash, "%s\n", hashrecord);
		free(hashrecord);
		}

	if(fhjohn != NULL)
		{
		combiline[64] = 0;
		fprintf(fhjohn, "$pbkdf2-hmac-sha1$4096$");
		for(c = 0; c < essidlen; c++)
			fprintf(fhjohn, "%02x", essidname[c]);
		fprintf(fhjohn, "$%s\n", combiline);
		}
	hashcount++;
	}
printf("\r%ld hashrecords generated, %ld password(s) skipped\n", hashcount, skippedcount);
return;
}
/*===========================================================================*/
static void outputsinglehash(char *pmkname, char *essidname, int essidlen)
{
int c;
char *hashrecord = NULL;
unsigned char essidstr[64];
unsigned char pmkstr[64];

if(hexstr2bin(pmkname, pmkstr, 64) != true)
	{
	fprintf(stderr, "error wrong plainmasterkey\n");
	return;
	}

printf("\nhashcat: hash-mode -m 12000 to get password\n");
memset(&essidstr, 0, 64);
memcpy(&essidstr, essidname, essidlen);
base64(essidstr, essidlen, &hashrecord);
printf("sha1:4096:%s:", hashrecord);
free(hashrecord);
base64(pmkstr, 32, &hashrecord);
printf("%s\n\n", hashrecord);
free(hashrecord);
printf("\njohn: pbkdf2-hmac-sha1 to get password\n");
printf("$pbkdf2-hmac-sha1$4096$");
for(c = 0; c < essidlen; c++)
	printf("%02x", essidname[c]);
printf("$%s\n\n", pmkname);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file>  : input combilist (pmk:essid)\n"
 	"-o <file>  : output hashcat hashfile (-m 12000)\n"
 	"-j <file>  : output john hashfile (pbkdf2-hmac-sha1)\n"
	"-e <essid> : input single essid (networkname: 1 .. 32 characters)\n"
	"-p <pmk>   : input plainmasterkey (64 xdigits)\n"
	"-h         : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int p;
int essidlen = 0;
int pmklen = 0;
char *pmkname = NULL;
char *essidname = NULL;

FILE *fhcombi = NULL;
FILE *fhhash = NULL;
FILE *fhjohn = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:j:e:p:h")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		if((fhcombi = fopen(optarg, "r")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		if((fhhash = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'j':
		if((fhjohn = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
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
		pmkname = optarg;
		pmklen = strlen(pmkname);
		if(pmklen != 64)
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

		default:
		usage(basename(argv[0]));
		}
	}

if((essidname != NULL) && (pmkname != NULL))
	outputsinglehash(pmkname, essidname, essidlen);

else if((fhcombi != NULL) && ((fhhash != NULL) || (fhjohn != NULL)))
	outputhashlist(fhcombi, fhhash, fhjohn);


if(fhcombi != NULL)
	fclose(fhcombi);

if(fhjohn != NULL)
	fclose(fhjohn);

if(fhhash != NULL)
	fclose(fhhash);


return EXIT_SUCCESS;
}

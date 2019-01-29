#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include <curl/curl.h>

#include "include/version.h"
#include "common.h"


#define COWPATTY_SIGNATURE 0x43575041L

struct cow_head
{
 uint32_t magic;
 uint8_t reserved1[3];
 uint8_t essidlen;
 uint8_t essid[32];
};
typedef struct cow_head cow_head_t;
#define	COWHEAD_SIZE (sizeof(cow_head_t))

/*===========================================================================*/
/* globale Konstante */

static const uint8_t zeroessid[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define ZEROESSID_SIZE sizeof(zeroessid)

/*===========================================================================*/
static void cowinfo(FILE *fhcowin)
{
int rd;
cow_head_t cowh;

char networkname[34];


rd = fread(&cowh, COWHEAD_SIZE, 1, fhcowin);
if(rd != 1)
	{
	fprintf(stderr, "error reading cowpatty file header\n");
	return;
	}

if(cowh.magic != COWPATTY_SIGNATURE)
	{
	fprintf(stderr, "signature doesn't match\n");
	return;
	}


if((cowh.essidlen == 0) && (memcmp(&cowh.essid, &zeroessid, ZEROESSID_SIZE) == 0) && (cowh.reserved1[2] == 1))
	{
	printf("Multi-ESSID file detected\n");
	return;
	}

if((cowh.essidlen == 0) || (cowh.essidlen > 32))
	{
	fprintf(stderr, "wrong essidlen\n");
	return;
	}

memset(&networkname, 0, 34);
memcpy(&networkname, &cowh.essid, cowh.essidlen);
printf("essid: %s\n", networkname);

return;
}
/*===========================================================================*/
static void cowprocess(FILE *fhcowin, FILE *fhpwout, FILE *fhpmkpwout, FILE *fhpmkout, const int mode)
{
int rd, c;
uint8_t pwlen = 0;
cow_head_t cowh;

uint8_t recsize;
uint8_t cowrec[100];
char passwort[66];

rd = fread(&cowh, COWHEAD_SIZE, 1, fhcowin);
if(rd != 1)
	{
	fprintf(stderr, "error reading cowpatty file header\n");
	return;
	}

if(cowh.magic != COWPATTY_SIGNATURE)
	{
	fprintf(stderr, "signature doesn't match\n");
	return;
	}

if((cowh.essidlen == 0) && (memcmp(&cowh.essid, &zeroessid, ZEROESSID_SIZE) == 0) && (cowh.reserved1[2] == 1))
	printf("Multi-ESSID file detected\n");


else if((cowh.essidlen == 0) || (cowh.essidlen > 32))
	{
	fprintf(stderr, "wrong essidlen\n");
	return;
	}

while( fread(&recsize, sizeof(uint8_t), 1, fhcowin) ==1)
	{
	if((recsize < 33) || (recsize > 92))
		{
		fprintf(stderr, "error reading record size\n");
		return;
		}
	recsize--;
	rd = fread(&cowrec, sizeof(uint8_t), recsize, fhcowin);
	if(rd != recsize)
		{
		fprintf(stderr, "error reading record size\n");
		return;
		}

	pwlen = recsize -32;
	memset(&passwort, 0, 66);
	memcpy(&passwort, &cowrec, pwlen);

	if(fhpwout != NULL)
		fprintf(fhpwout, "%s\n", passwort);

	if(fhpmkpwout != NULL)
		{
		for(c = pwlen; c < recsize; c++)
			fprintf(fhpmkpwout, "%02x", cowrec[c]);
		fprintf(fhpmkpwout, ":%s\n", passwort);
		}

	if(fhpmkout != NULL)
		{
		for(c = pwlen; c < recsize; c++)
			fprintf(fhpmkout, "%02x", cowrec[c]);
		fprintf(fhpmkout, "\n");
		}

	if(mode == 's')
		{
		for(c = pwlen; c < recsize; c++)
			fprintf(stdout, "%02x", cowrec[c]);
		fprintf(stdout, "\n");
		}
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"options:\n"
	"-i <file> : input cowpatty hashfile\n"
	"-w <file> : output passwordlist file\n"
	"-W <file> : output pmk:password file\n"
	"-p <file> : output pmk file\n"
	"-s        : print pmk's to stdout\n"
	"-h        : this help file\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
uint8_t mode = 0;
char *cowinname = NULL;
char *pwoutname = NULL;
char *pmkpwoutname = NULL;
char *pmkoutname = NULL;

FILE *fhcowin = NULL;
FILE *fhpwout = NULL;
FILE *fhpmkpwout = NULL;
FILE *fhpmkout = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:w:W:p:shv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		cowinname = optarg;
		if((fhcowin = fopen(cowinname, "rb")) == NULL)
			{
			fprintf(stderr, "error opening cowpatty hashfile file %s\n", cowinname);
			exit(EXIT_FAILURE);
			}
		break;

		case 'w':
		pwoutname = optarg;
		if((fhpwout = fopen(pwoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening file %s\n", pwoutname);
			exit(EXIT_FAILURE);
			}
		break;

		case 'W':
		pmkpwoutname = optarg;
		if((fhpmkpwout = fopen(pmkpwoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening file %s\n", pmkpwoutname);
			exit(EXIT_FAILURE);
			}
		break;

		case 'p':
		pmkoutname = optarg;
		if((fhpmkout = fopen(pmkoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening file %s\n", pmkoutname);
			exit(EXIT_FAILURE);
			}
		break;

		case 's':
		mode = 's';
		break;

		default:
		usage(basename(argv[0]));
		}
	}

if(fhcowin == NULL)
	{
	fprintf(stderr, "no cowpatty hashfile selected\n");
	exit(EXIT_FAILURE);
	}

if((mode != 's') && (fhpwout == NULL) && (fhpmkpwout == NULL) && (fhpmkout == NULL))
	{
	cowinfo(fhcowin);
	fclose(fhcowin);
	return EXIT_SUCCESS;
	}

cowprocess(fhcowin, fhpwout, fhpmkpwout, fhpmkout, mode);

if(fhpwout != NULL)
	fclose(fhpwout);

if(fhpmkpwout != NULL)
	fclose(fhpmkpwout);

if(fhpmkout != NULL)
	fclose(fhpmkout);

if(fhcowin != NULL)
	fclose(fhcowin);

return EXIT_SUCCESS;
}

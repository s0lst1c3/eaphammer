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
#include "common.c"
#include "com_md5_64.c"
#include "com_formats.c"

/*===========================================================================*/
/* globale Variablen */

static hcx_t *hcxdata = NULL;
/*===========================================================================*/
static void hashhcx(long int hcxrecords, FILE* fhhash)
{
hcx_t *zeigerhcx;
long int c;

char outstr[1024];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(showhashrecord(zeigerhcx, NULL, 0, outstr) == true)
		fprintf(fhhash, "%s\n", outstr);
	c++;
	}
return;
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
		return false;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
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
	"-S <file> : output info for identified hccapx handshake to file\n"
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
long int hcxorgrecords = 0;
FILE *fhhash;
char *hcxinname = NULL;
char *hashoutname = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:S:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'S':
		hashoutname = optarg;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

if(hashoutname != NULL)
	{
	if((fhhash = fopen(hashoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", hashoutname);
		exit(EXIT_FAILURE);
		}
	hashhcx(hcxorgrecords, fhhash);
	fclose(fhhash);
	}
else
	hashhcx(hcxorgrecords, stdout);



if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

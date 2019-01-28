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
static hcx_t *hcxdata2 = NULL;

/*===========================================================================*/
static int sort_by_essid(const void *a, const void *b)
{
const hcx_t *ia = (const hcx_t *)a;
const hcx_t *ib = (const hcx_t *)b;

return memcmp(ia->essid, ib->essid, 32);
}
/*===========================================================================*/
static bool writehccapx(char *hcxoutname, long int hcxrecords, long int hcxrecords2)
{
hcx_t *zeigerhcx;
hcx_t *zeigerhcx1;
hcx_t *zeigerhcx2;

FILE *fhhcx;
long int c, c2;

if(hcxoutname == NULL)
	return false;

if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxoutname);
	return false;
	}

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_essid);
qsort(hcxdata2, hcxrecords2, HCX_SIZE, sort_by_essid);

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	zeigerhcx1 = hcxdata +c +1;
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	if((zeigerhcx->essid_len == zeigerhcx1->essid_len) && (memcmp(zeigerhcx->essid, zeigerhcx1->essid, zeigerhcx->essid_len) == 0))
		{
		c++;
		continue;
		}

	zeigerhcx2 = hcxdata2;
	c2 = 0;
	while(c2 < hcxrecords2)
		{
		if((zeigerhcx->essid_len == zeigerhcx2->essid_len) && (memcmp(zeigerhcx->essid, zeigerhcx2->essid, zeigerhcx->essid_len) == 0))
			fwrite(zeigerhcx2, HCX_SIZE, 1, fhhcx);
		zeigerhcx2++;
		c2++;
		}

	c++;
	}
fclose(fhhcx);
return true;
}
/*===========================================================================*/
static long int readhccapx2(char *hcxinname)
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

hcxdata2 = malloc(statinfo.st_size);
if(hcxdata2 == NULL)
		{
		fprintf(stderr, "out of memory to store second hccapx data\n");
		fclose(fhhcx);
		return 0;
		}

hcxsize = fread(hcxdata2, 1, statinfo.st_size +HCX_SIZE, fhhcx);
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
	"-i <file> : input hccapx file\n"
	"-s <file> : input second hccapx file\n"
	"-o <file> : output hccapx file (merged by essid)\n"
	"-I        : show info about hccapx file\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
long int hcxorgrecords = 0;
long int hcxorgrecords2 = 0;

char *hcxinname = NULL;
char *hcxinname2 = NULL;
char *hcxoutname = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:s:o:Ihv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'o':
		hcxoutname = optarg;
		break;

		case 's':
		hcxinname2 = optarg;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

hcxorgrecords = readhccapx(hcxinname);
if(hcxorgrecords == 0)
	return EXIT_SUCCESS;

hcxorgrecords2 = readhccapx2(hcxinname2);
if(hcxorgrecords2 == 0)
	return EXIT_SUCCESS;

writehccapx(hcxoutname, hcxorgrecords, hcxorgrecords2);


if(hcxdata2 != NULL)
	free(hcxdata2);


if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

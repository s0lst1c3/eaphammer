/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: utils.h,v 1.8 2007/05/10 19:29:06 jwright Exp $
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

/* Prototypes */
void lamont_hdump(unsigned char *bp, unsigned int length);
unsigned char Get7Bits(unsigned char *input, int startBit);
void MakeKey(unsigned char *key, unsigned char *des_key);
void Expand(unsigned char *in, unsigned char *out);
void Collapse(unsigned char *in, unsigned char *out);
void DesEncrypt(unsigned char *clear, unsigned char *key,
		unsigned char *cipher);
int IsBlank(char *s);
char *printmac(unsigned char *mac);
int str2hex (char *string, uint8_t *hexstr, int len);

/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: asleap.h,v 1.17 2007/05/10 19:29:06 jwright Exp $
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

/* These offsets follow start at the beginning of the IP Header */
//#define GREOFFSET   20
#define IPHDRLEN   20		/* Not always constant, but usually */
#define GREMINHDRLEN 8
#define GRESYNSETFLAG 0x0010
#define GREACKSETFLAG 0x8000
//#define PPPGREOFFSET  16
#define PPPGRECHAPOFFSET 2
#define PPPUSERNAMEOFFSET 54

#define LPEXCH_ERR -1
#define LPEXCH_TIMEOUT 0
#define LEAPEXCHFOUND 1
#define PPTPEXCHFOUND 2

#define GREPROTOPPP 0x880b
#define PPPPROTOCHAP 0xc223

/* asleap data structure, containing information from command line options and
   gathered information from the network.
   XXX This should *really* be broken up into two structures for command line
   configuration information and packet capture results.  Such is the result
   of poor planning in the initial design. */
struct asleap_data {
	char username[256 + 1];
	uint8_t eapid;
	uint8_t challenge[8];
	uint8_t response[24];
	uint8_t endofhash[2];
	char password[32];
	uint8_t nthash[16];
	/* for PPTP/true MS-CHAPv2 */
	uint8_t pptpauthchal[16];
	uint8_t pptppeerchal[16];
//    uint8_t    pptpchal[8];
//    uint8_t    pptppeerresp[24];

	int eapsuccess;
	int skipeapsuccess;	/* Don't bother checking for success after auth */
	int verbose;
	char dictfile[255];
	char dictidx[255];
	char wordfile[255];

	/* Tracking values */
	uint8_t leapchalfound;
	uint8_t leaprespfound;
	uint8_t leapsuccessfound;
	uint8_t pptpchalfound;
	uint8_t pptprespfound;
	uint8_t pptpsuccessfound;
	uint8_t manualchalresp;
};


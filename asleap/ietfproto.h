/* Copyright 2006 Aruba Networks */

/* Layer 3+ protocol definitions and constants */

#ifndef IETFPROTO_H
#define IETFPROTO_H

/* EAP message constants */
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4

/* EAP types, more at http://www.iana.org/assignments/eap-numbers */
#define EAP_TYPE_EAP	0
#define EAP_TYPE_ID     1
#define EAP_TYPE_NOTIFY 2
#define EAP_TYPE_NAK    3
#define EAP_TYPE_MD5    4
#define EAP_TYPE_TLS    13
#define EAP_TYPE_LEAP   17
#define EAP_TYPE_SIM    18
#define EAP_TYPE_TTLS   21
#define EAP_TYPE_AKA    23
#define EAP_TYPE_PEAP   25
#define EAP_TYPE_MSCHAPV2 26
#define EAP_TYPE_FAST   43

struct eap_hdr {
	uint8_t    code; /* 1=request, 2=response, 3=success, 4=failure? */
	uint8_t    identifier;
	uint16_t   length; /* Length of the entire EAP message */

	/* The following fields may not be present in all EAP frames */
	uint8_t    type;
	uint8_t    flags;
	uint32_t   totallen;
} __attribute__ ((packed));
#define EAPHDR_MIN_LEN 4
#define EAPHDR_INITFRAGHDR_LEN 6
#define EAPHDR_NEXTFRAGHDR_LEN 2

struct eap_leap_hdr {
	uint8_t    type;	/* hack, where does this belong? */
	uint8_t    version; /* Always 1 in my tests */
	uint8_t    reserved;
	uint8_t    count; /* Length in octets of the challenge/response field */
} __attribute__ ((packed));
#define EAPLEAPHDR_LEN sizeof(struct eap_leap_hdr);
#define EAPLEAP_MIN_REQ_LEN 12
#define EAPLEAP_MIN_RESP_LEN 28

#define EAP_TLS_FLAG_LEN 0x80 /* Length included */
#define EAP_TLS_FLAG_MOREFRAG 0x40 /* More fragments  */
#define EAP_TLS_FLAG_START 0x20 /* EAP-TLS start   */
#define EAP_PEAP_FLAG_VERSION 0x07 /* EAP-PEAP version */

/* IP protocol header */
struct iphdr {
	uint8_t		ver_hlen;
	uint8_t		tos;
	uint16_t	len;
	uint16_t	ipid;
	uint16_t	flags_offset;
	uint8_t		ttl;
	uint8_t		proto;
	uint16_t	checksum;
	uint8_t		srcaddr[4];
	uint8_t		dstaddr[4];
} __attribute__ ((packed));
#define IPHDR_LEN sizeof(struct iphdr)
#define IPHDR_MIN_LEN 20
#define IPHDR_MAX_LEN 64

struct tcphdr {
	uint16_t	sport;
	uint16_t	dport;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		hlen;
	uint8_t		flags;
	uint16_t	wsize;
	uint16_t	checksum;
} __attribute__ ((packed));
#define TCPHDR_LEN sizeof(struct tcphdr)

struct udphdr {
	uint16_t	sport;
	uint16_t	dport;
	uint16_t	hlen;
	uint16_t	checksum;
} __attribute__ ((packed));
#define UDPHDR_LEN sizeof(struct udphdr)

/* This is the structure of the GRE header */
struct grehdr {
	uint16_t   flags;
	uint16_t   type;
	uint16_t   length;
	uint16_t   callid;
	uint16_t   seq; /* optional based on flags */
	uint16_t   ack; /* optional based on flags */
} __attribute__ ((packed));
#define GREHDR_MIN_LEN (sizeof(struct grehdr) - 4)
#define GREPROTO_PPP 0x880b
#define GRE_FLAG_SYNSET 0x0010
#define GRE_FLAG_ACKSET 0x8000

#define TCP_PORT_PPTP 1723
#define UDP_PORT_L2TP 1701

/* This is the structure of the Point-to-Point Protocol header */
struct ppphdr {
	uint16_t   proto;
} __attribute__ ((packed));
#define PPPHDR_LEN sizeof(struct ppphdr)
#define PPPPROTO_CHAP 0xc223

/* This is the structure of the PPP CHAP header */
struct pppchaphdr {
	uint8_t    code;
	uint8_t    identifier;
	uint16_t   length;
	union {
		struct {
			uint8_t    datalen;
			uint8_t    authchal[16];
		} chaldata;
		struct {
			uint8_t    datalen;
			uint8_t    peerchal[16];
			uint8_t    unknown[8]; /* all zero's */
			uint8_t    peerresp[24];
			uint8_t    state;
			uint8_t    name;
		} respdata;
	} u;
} __attribute__ ((packed));
#define PPPCHAPHDR_LEN 4
#define PPPCHAPHDR_MIN_CHAL_LEN 21
#define PPPCHAPHDR_MIN_RESP_LEN 55
#define PPPCHAP_CHALLENGE   1
#define PPPCHAP_RESPONSE    2
#define PPPCHAP_SUCCESS     3
#define PPPCHAP_FAILURE     4

struct arphdr {
	uint16_t	hwtype;       /* format of hardware address   */
	uint16_t	prototype;    /* format of protocol address   */
	uint8_t		hwlen;        /* length of hardware address   */
	uint8_t		protolen;     /* length of protocol address   */
	uint16_t	opcode;       /* ARP opcode (command)         */
};

struct arpreq {
	struct	arphdr	arph;
	uint8_t		req[20];
};

#define ARPHDR_LEN sizeof(struct arphdr);
#define ARPREQ_LEN sizeof(struct arpreq);

#define ARP_REQUEST   1    /* ARP request                  */
#define ARP_REPLY     2    /* ARP reply                    */
#define ARP_RREQUEST  3    /* RARP request                 */
#define ARP_RREPLY    4    /* RARP reply                   */


struct tlsrec_hdr {
	uint8_t		type;
	uint16_t	ver;
	uint16_t	len;
} __attribute__ ((packed));
#define TLSRECHDR_LEN sizeof(struct tlsrec_hdr)

struct tlshshake_hdr {
	uint8_t		type;
	uint8_t		len[3]; /* 3 bytes WTF */
} __attribute__ ((packed));
#define TLSHSHAKEHDR_LEN sizeof(struct tlshshake_hdr)



#endif

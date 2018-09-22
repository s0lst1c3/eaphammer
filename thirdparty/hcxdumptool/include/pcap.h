#define PCAPMAGICNUMBER 0xa1b2c3d4
#define PCAPMAGICNUMBERBE 0xd4c3b2a1


#define PCAPNGBLOCKTYPE 0x0a0d0d0a
#define PCAPNGMAGICNUMBER 0x1a2b3c4d
#define PCAPNGMAGICNUMBERBE 0x4d3c2b1a

#define PCAPNG_MAJOR_VER 1
#define PCAPNG_MINOR_VER 0
#define PCAPNG_MAXSNAPLEN 0xffff


/*===========================================================================*/
/* Section Header Block (SHB) - ID 0x0A0D0D0A */
struct section_header_block_s
{
 uint32_t	block_type;		/* block type */
 uint32_t	total_length;		/* block length */
 uint32_t	byte_order_magic;	/* byte order magic - indicates swapped data */
 uint16_t	major_version;		/* major version of pcapng (1 atm) */
 uint16_t	minor_version;		/* minor version of pcapng (0 atm) */
 int64_t	section_length;		/* length of section - can be -1 (parsing necessary) */
} __attribute__((__packed__));
typedef struct section_header_block_s section_header_block_t;
#define	SHB_SIZE (sizeof(section_header_block_t))
/*===========================================================================*/
/* Header of all pcapng blocks */
struct block_header_s
{
 uint32_t	block_type;	/* block type */
 uint32_t	total_length;	/* block length */
} __attribute__((__packed__));
typedef struct block_header_s block_header_t;
#define	BH_SIZE (sizeof(block_header_t))
/*===========================================================================*/
/* total lenght*/
struct total_length_s
{
 uint32_t	total_length;
} __attribute__((__packed__));
typedef struct total_length_s total_length_t;
#define	TOTAL_SIZE (sizeof(total_length_t))
/*===========================================================================*/
/* Header of all pcapng options */
struct option_header_s
{
#define SHB_EOC		0
#define SHB_COMMENT	1
#define SHB_HARDWARE	2
#define SHB_OS		3
#define SHB_USER_APPL	4

#define IF_NAME		2
#define IF_DESCRIPTION	3
#define IF_MACADDR	6
#define IF_TZONE	10

 uint16_t		option_code;	/* option code - depending of block (0 - end of opts, 1 - comment are in common) */
 uint16_t		option_length;	/* option length - length of option in bytes (will be padded to 32bit) */
 char			option_data[1];
} __attribute__((__packed__));
typedef struct option_header_s option_header_t;
#define	OH_SIZE (sizeof(option_header_t))
/*===========================================================================*/
/* Option Field */
struct optionfield64_s
{
 uint16_t	option_code;
 uint16_t	option_length;
 uint64_t	option_value;
} __attribute__((__packed__));
typedef struct optionfield64_s optionfield64_t;
#define	OPTIONFIELD64_SIZE offsetof(optionfield64_t, data)
/*===========================================================================*/
/* Interface Description Block (IDB) - ID 0x00000001 */
struct interface_description_block_s
 {
 uint32_t	block_type;		/* block type */
#define	IDBID	0x00000001;
 uint32_t	total_length;		/* block length */
 uint16_t	linktype;		/* the link layer type (was -network- in classic pcap global header) */
#define	DLT_IEEE802_11_RADIO	127
 uint16_t	reserved;		/* 2 bytes of reserved data */
 uint32_t	snaplen;		/* maximum number of bytes dumped from each packet (was -snaplen- in classic pcap global header */
} __attribute__((__packed__));
typedef struct interface_description_block_s interface_description_block_t;
#define	IDB_SIZE (sizeof(interface_description_block_t))
/*===========================================================================*/
/* Packet Block (PB) - ID 0x00000002 (OBSOLETE - EPB should be used instead) */
struct packet_block_s
{
 uint32_t	block_type;		/* block type */
 uint32_t	total_length;		/* block length */
 uint16_t	interface_id;		/* the interface the packet was captured from - identified by interface description block in current section */
 uint16_t	drops_count;		/* packet dropped by IF and OS since prior packet */
 uint32_t	timestamp_high;		/* high bytes of timestamp */
 uint32_t	timestamp_low;		/* low bytes of timestamp */
 uint32_t	cap_len;		/* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
 uint32_t	org_len;		/* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} __attribute__((__packed__));
typedef struct packet_block_s packet_block_t;
#define	PB_SIZE (sizeof(packet_block_t))
/*===========================================================================*/
/* Simple Packet Block (SPB) - ID 0x00000003 */
struct simple_packet_block_s
{
 uint32_t	block_type;		/* block type */
 uint32_t	total_length;		/* block length */
 uint32_t	original_len;		/* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} __attribute__((__packed__));
typedef struct simple_packet_block_s simple_packet_block_t;
#define	SPB_SIZE (sizeof(simple_packet_block_t))
/*===========================================================================*/
/* Name Resolution Block (NRB) - ID 0x00000004 */
struct name_resolution_block_s
{
 uint32_t	block_type;		/* block type */
 uint32_t	total_length;		/* block length */
 uint16_t	record_type;		/* type of record (ipv4 / ipv6) */
 uint16_t	record_length;		/* length of record value */
} __attribute__((__packed__));
typedef struct name_resolution_block_s name_resolution_block_t;
#define	NRB_SIZE (sizeof(name_resolution_block_t))
/*===========================================================================*/
/* Interface Statistics Block - ID 0x00000005 */
struct interface_statistics_block_s
{
 uint32_t	block_type;		/* block type */
#define	ISBID	0x00000005;
 uint32_t	total_length;		/* block length */
 uint32_t	interface_id;		/* the interface the stats refer to - identified by interface description block in current section */
 uint32_t	timestamp_high;		/* high bytes of timestamp */
 uint32_t	timestamp_low;		/* low bytes of timestamp */
#define ISB_STARTTIME		2
#define ISB_ENDTIME		3
#define ISB_IFRECV		4
#define ISB_IFDROP		5
#define ISB_FILTERACCEPT	6
#define ISB_OSDROP		7
#define ISB_USRDELIV		8
 uint16_t	code_starttime;
 uint16_t	starttime_len;
 uint32_t	starttime_timestamp_high;	/* high bytes of timestamp */
 uint32_t	starttime_timestamp_low;	/* low bytes of timestamp */

 uint16_t	code_endtime;
 uint16_t	endtime_len;
 uint32_t	endtime_timestamp_high;	/* high bytes of timestamp */
 uint32_t	endtime_timestamp_low;	/* low bytes of timestamp */

 uint16_t	code_recv;
 uint16_t	recv_len;
 uint64_t	recv;

 uint16_t	code_ifdrop;
 uint16_t	ifdrop_len;
 uint64_t	ifdrop;

 uint16_t	code_filteraccept;
 uint16_t	filteraccept_len;
 uint64_t	filteraccept;

 uint16_t	code_osdrop;
 uint16_t	osdrop_len;
 uint64_t	osdrop;

 uint16_t	code_usredliv;
 uint16_t	usredliv_len;
 uint64_t	usredliv;

 uint16_t	code_eoo;
 uint16_t	eoo_len;
 uint32_t	total_length_dup;		/* block length */
} __attribute__((__packed__));
typedef struct interface_statistics_block_s interface_statistics_block_t;
#define	ISB_SIZE (sizeof(interface_statistics_block_t))
/*===========================================================================*/
/* Enhanced Packet Block (EPB) - ID 0x00000006 */
struct enhanced_packet_block_s
{
 uint32_t	block_type;		/* block type */
#define EPBBID	0x00000006;
 uint32_t	total_length;		/* block length */
 uint32_t	interface_id;		/* the interface the packet was captured from - identified by interface description block in current section */
 uint32_t	timestamp_high;		/* high bytes of timestamp */
 uint32_t	timestamp_low;		/* low bytes of timestamp */
 uint32_t	cap_len;		/* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
 uint32_t	org_len;		/* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} __attribute__((__packed__));
typedef struct enhanced_packet_block_s enhanced_packet_block_t;
#define	EPB_SIZE (sizeof(enhanced_packet_block_t))
/*===========================================================================*/

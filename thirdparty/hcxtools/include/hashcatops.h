#define	MESSAGE_PAIR_M12E2 0
#define	MESSAGE_PAIR_M14E4 1
#define	MESSAGE_PAIR_M32E2 2
#define	MESSAGE_PAIR_M32E3 3
#define	MESSAGE_PAIR_M34E3 4
#define	MESSAGE_PAIR_M34E4 5

/*===========================================================================*/
struct hccapx_s
{
 uint32_t	signature;
#define HCCAPX_SIGNATURE 0x58504348
 uint32_t	version;
#define HCCAPX_VERSION 4
 uint8_t	message_pair;
 uint8_t	essid_len;
 uint8_t	essid[32];
 uint8_t	keyver;
 uint8_t	keymic[16];
 uint8_t	mac_ap[6];
 uint8_t	nonce_ap[32];
 uint8_t	mac_sta[6];
 uint8_t	nonce_sta[32];
 uint16_t	eapol_len;
 uint8_t	eapol[256];
} __attribute__((packed));
typedef struct hccapx_s hccapx_t;
#define	HCCAPX_SIZE (sizeof(hccapx_t))
/*===========================================================================*/
struct hccap_s
{
  char essid[36];
  unsigned char mac1[6];	/* bssid */
  unsigned char mac2[6];	/* client */
  unsigned char nonce1[32];	/* snonce client */
  unsigned char nonce2[32];	/* anonce bssid */
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap_s hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))
/*===========================================================================*/
struct pmklist_s
{
 uint8_t pmk[32];
 bool essidflag;
 uint8_t essidlen;
 uint8_t essid[32];
 bool pskflag;
 uint8_t psklen;
 uint8_t psk[64];
} __attribute__((__packed__));
typedef struct pmklist_s pmklist_t;
#define	PMKLIST_SIZE (sizeof(pmklist_t))
/*===========================================================================*/

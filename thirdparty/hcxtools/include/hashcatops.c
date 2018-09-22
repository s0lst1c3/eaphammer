#include <stdbool.h>
#include <stddef.h>
#include "hashcatops.h"

/*===========================================================================*/
void writehccapxrecord(hcxl_t *zeiger, FILE *fho)
{
hccapx_t hccapx;
wpakey_t *wpak, *wpak2;

memset (&hccapx, 0, sizeof(hccapx_t));
hccapx.signature = HCCAPX_SIGNATURE;
hccapx.version   = HCCAPX_VERSION;
hccapx.message_pair = 0x80;
if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 4))
	{
	hccapx.message_pair = MESSAGE_PAIR_M12E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 4))
	{
	hccapx.message_pair = MESSAGE_PAIR_M32E2;
	if(zeiger->replaycount_ap -1 != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 8))
	{
	hccapx.message_pair = MESSAGE_PAIR_M14E4;
	if(zeiger->replaycount_ap +1 != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 8))
	{
	hccapx.message_pair = MESSAGE_PAIR_M34E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}
hccapx.message_pair |= zeiger->endianess;
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
hccapx.essid_len = zeiger->essidlen;
memcpy(&hccapx.essid, zeiger->essid, 32);
memcpy(&hccapx.mac_ap, zeiger->mac_ap, 6);
memcpy(&hccapx.nonce_ap, zeiger->nonce, 32);
memcpy(&hccapx.mac_sta, zeiger->mac_sta, 6);
memcpy(&hccapx.nonce_sta, wpak->nonce, 32);
hccapx.eapol_len = zeiger->authlen;
memcpy(&hccapx.eapol, zeiger->eapol, zeiger->authlen);
memcpy(&hccapx.keymic, wpak->keymic, 16);
wpak2 = (wpakey_t*)(hccapx.eapol +EAPAUTH_SIZE);
memset(wpak2->keymic, 0, 16);
hccapx.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
 #ifdef BIG_ENDIAN_HOST
hccapx.signature	= byte_swap_32(hccapx.signature);
hccapx.version		= byte_swap_32(hccapx.version);
hccapx.eapol_len	= byte_swap_16(hccapx.eapol_len);
#endif
fwrite (&hccapx, sizeof(hccapx_t), 1, fho);
return;
}
/*===========================================================================*/
void writehccaprecord(unsigned long long int noncefuzz, hcxl_t *zeiger, FILE *fho)
{
hccap_t hccap;
wpakey_t *wpak, *wpak2;
unsigned int n;
unsigned int anonce;

memset (&hccap, 0, sizeof(hccap_t));
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
memcpy(&hccap.essid, zeiger->essid, 32);
memcpy(&hccap.mac1, zeiger->mac_ap, 6);
memcpy(&hccap.mac2, zeiger->mac_sta, 6);
memcpy(&hccap.nonce1, wpak->nonce, 32);
memcpy(&hccap.nonce2, zeiger->nonce, 32);

hccap.eapol_size = zeiger->authlen;
memcpy(&hccap.eapol, zeiger->eapol, zeiger->authlen);
memcpy(&hccap.keymic, wpak->keymic, 16);
wpak2 = (wpakey_t*)(hccap.eapol +EAPAUTH_SIZE);
memset(wpak2->keymic, 0, 16);
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
 #ifdef BIG_ENDIAN_HOST
hccap.eapolsize	= byte_swap_16(hccap.eapolsize);
#endif

if((zeiger->endianess & 0x10) == 0x10)
	{
	fwrite (&hccap, sizeof(hccap_t), 1, fho);
	}
else if((zeiger->endianess & 0x20) == 0x20)
	{
	anonce = zeiger->nonce[31] | (zeiger->nonce[30] << 8) | (zeiger->nonce[29] << 16) | (zeiger->nonce[28] << 24);
	anonce -= noncefuzz/2;
	for (n = 0; n < noncefuzz; n++)
		{
		hccap.nonce2[28] = (anonce >> 24) & 0xff;
		hccap.nonce2[29] = (anonce >> 16) & 0xff;
		hccap.nonce2[30] = (anonce >> 8) & 0xff;
		hccap.nonce2[31] = anonce & 0xff;
		fwrite (&hccap, sizeof(hccap_t), 1, fho);
		anonce++;
		}
	}
else if((zeiger->endianess & 0x40) == 0x40)
	{
	anonce = zeiger->nonce[28] | (zeiger->nonce[29] << 8) | (zeiger->nonce[30] << 16) | (zeiger->nonce[31] << 24);
	anonce -= noncefuzz/2;
	for (n = 0; n < noncefuzz; n++)
		{
		hccap.nonce2[31] = (anonce >> 24) & 0xff;
		hccap.nonce2[30] = (anonce >> 16) & 0xff;
		hccap.nonce2[29] = (anonce >> 8) & 0xff;
		hccap.nonce2[28] = anonce & 0xff;
		fwrite (&hccap, sizeof(hccap_t), 1, fho);
		anonce++;
		}
	}
else
	{
	anonce = zeiger->nonce[31] | (zeiger->nonce[30] << 8) | (zeiger->nonce[29] << 16) | (zeiger->nonce[28] << 24);
	anonce -= noncefuzz/2;
	for (n = 0; n < noncefuzz; n++)
		{
		hccap.nonce2[28] = (anonce >> 24) & 0xff;
		hccap.nonce2[29] = (anonce >> 16) & 0xff;
		hccap.nonce2[30] = (anonce >> 8) & 0xff;
		hccap.nonce2[31] = anonce & 0xff;
		fwrite (&hccap, sizeof(hccap_t), 1, fho);
		anonce++;
		}
	anonce = zeiger->nonce[28] | (zeiger->nonce[29] << 8) | (zeiger->nonce[30] << 16) | (zeiger->nonce[31] << 24);
	anonce -= noncefuzz/2;
	for (n = 0; n < noncefuzz; n++)
		{
		hccap.nonce2[31] = (anonce >> 24) & 0xff;
		hccap.nonce2[30] = (anonce >> 16) & 0xff;
		hccap.nonce2[29] = (anonce >> 8) & 0xff;
		hccap.nonce2[28] = anonce & 0xff;
		fwrite (&hccap, sizeof(hccap_t), 1, fho);
		anonce++;
		}
	}
return;
}
/*===========================================================================*/

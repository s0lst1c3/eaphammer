
/*===========================================================================*/
static void hccap2base(FILE *fhjohn, unsigned char *in, unsigned char b)
{
const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fprintf(fhjohn, "%c", (itoa64[in[0] >> 2]));
fprintf(fhjohn, "%c", (itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]));
if (b)
	{
	fprintf(fhjohn, "%c", (itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]));
	fprintf(fhjohn, "%c", (itoa64[in[2] & 0x3f]));
	}
else
	fprintf(fhjohn, "%c", (itoa64[((in[1] & 0x0f) << 2)]));
return;
}
/*===========================================================================*/
static void mac2asciilong(char ssid[18], unsigned char *p)
{
sprintf(ssid, "%02x-%02x-%02x-%02x-%02x-%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
static void mac2ascii(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x%02x%02x%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
static void writejohnrecord(unsigned long long int noncefuzz, hcxl_t *zeiger, FILE *fhjohn, char *basename)
{
hccap_t hccap;
wpakey_t *wpak, *wpak2;
uint8_t message_pair;
unsigned int i, n;
unsigned int anonce;
unsigned char *hcpos;
char sta_mac[18];
char ap_mac[18];
char ap_mac_long[13];

message_pair = 0x80;
if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 4))
	{
	message_pair = MESSAGE_PAIR_M12E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 4))
	{
	message_pair = MESSAGE_PAIR_M32E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta +1)
		{
		message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 3) && (zeiger->keyinfo_sta == 4))
	{
	message_pair = MESSAGE_PAIR_M32E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 8))
	{
	message_pair = MESSAGE_PAIR_M14E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta +1)
		{
		message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap >= 1) && (zeiger->keyinfo_sta == 8))
	{
	message_pair = MESSAGE_PAIR_M34E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		message_pair |= 0x80;
		}
	}

hcpos = (unsigned char*)&hccap;

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

mac2ascii(ap_mac_long, zeiger->mac_ap);
mac2asciilong(ap_mac, zeiger->mac_ap);
mac2asciilong(sta_mac, zeiger->mac_sta);

if(((zeiger->endianess & 0x10) == 0x10) || ((message_pair &0x10) == 0x10) || ((message_pair &0x80) == 0x00))
	{
	fprintf(fhjohn, "%s:$WPAPSK$%s#", hccap.essid, hccap.essid);
	for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
		{
		hccap2base(fhjohn, &hcpos[i], 1);
		}
	hccap2base(fhjohn, &hcpos[i], 0);
	fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
	if (hccap.keyver > 1)
		{
		fprintf(fhjohn, "%d", hccap.keyver);
		}
	if((message_pair &0x07) > 1)
		{
		fprintf(fhjohn, ":verfified:%s\n", basename);
		}
	else
		{
		fprintf(fhjohn, ":not verfified:%s\n", basename);
		}
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
		fprintf(fhjohn, "%s:$WPAPSK$%s#", hccap.essid, hccap.essid);
		for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
			{
			hccap2base(fhjohn, &hcpos[i], 1);
			}
		hccap2base(fhjohn, &hcpos[i], 0);
		fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
		if(hccap.keyver > 1)
			{
			fprintf(fhjohn, "%d", hccap.keyver);
			}
		if((message_pair &0x07) > 1)
			{
			fprintf(fhjohn, ":verfified:%s\n", basename);
			}
		else
			{
			fprintf(fhjohn, ":not verfified:%s\n", basename);
			}
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
		fprintf(fhjohn, "%s:$WPAPSK$%s#", hccap.essid, hccap.essid);
		for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
			{
			hccap2base(fhjohn, &hcpos[i], 1);
			}
		hccap2base(fhjohn, &hcpos[i], 0);
		fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
		if(hccap.keyver > 1)
			{
			fprintf(fhjohn, "%d", hccap.keyver);
			}
		if((message_pair &0x07) > 1)
			{
			fprintf(fhjohn, ":verfified:%s\n", basename);
			}
		else
			{
			fprintf(fhjohn, ":not verfified:%s\n", basename);
			}
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
		fprintf(fhjohn, "%s:$WPAPSK$%s#", hccap.essid, hccap.essid);
		for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
			{
			hccap2base(fhjohn, &hcpos[i], 1);
			}
		hccap2base(fhjohn, &hcpos[i], 0);
		fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
		if(hccap.keyver > 1)
			{
			fprintf(fhjohn, "%d", hccap.keyver);
			}
		if((message_pair &0x07) > 1)
			{
			fprintf(fhjohn, ":verfified:%s\n", basename);
			}
		else
			{
			fprintf(fhjohn, ":not verfified:%s\n", basename);
			}
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
		fprintf(fhjohn, "%s:$WPAPSK$%s#", hccap.essid, hccap.essid);
		for (i = 36; i + 3 < HCCAP_SIZE; i += 3)
			{
			hccap2base(fhjohn, &hcpos[i], 1);
			}
		hccap2base(fhjohn, &hcpos[i], 0);
		fprintf(fhjohn, ":%s:%s:%s::WPA", sta_mac, ap_mac, ap_mac_long);
		if(hccap.keyver > 1)
			{
			fprintf(fhjohn, "%d", hccap.keyver);
			}
		if((message_pair &0x07) > 1)
			{
			fprintf(fhjohn, ":verfified:%s\n", basename);
			}
		else
			{
			fprintf(fhjohn, ":not verfified:%s\n", basename);
			}
		anonce++;
		}
	}
return;
}
/*===========================================================================*/

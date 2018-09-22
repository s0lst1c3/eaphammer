void generatepkeprf(hcx_t *hcxrecord, uint8_t *pke_ptr);
void generatepke(hcx_t *hcxrecord, uint8_t *pke_ptr);
bool showhashrecord(hcx_t *hcxrecord, uint8_t *password, int pwlen, char *out);

/*===========================================================================*/
void generatepkeprf(hcx_t *hcxrecord, uint8_t *pke_ptr)
{
memcpy(pke_ptr, "Pairwise key expansion", 22);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 22, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 28, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 22, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 28, hcxrecord->mac_ap.addr,  6);
	}
if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 34, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 66, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 34, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 66, hcxrecord->nonce_ap,  32);
	}
return;
}
/*===========================================================================*/
void generatepke(hcx_t *hcxrecord, uint8_t *pke_ptr)
{
memcpy(pke_ptr, "Pairwise key expansion", 23);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 29, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 29, hcxrecord->mac_ap.addr,  6);
	}

if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_ap,  32);
	}
return;
}
/*===========================================================================*/
bool showhashrecord(hcx_t *hcxrecord, uint8_t *password, int pwlen, char *out)
{
int i;
hcxhrc_t hashrec;
uint32_t hash[4];
uint32_t block[16];
uint8_t *block_ptr = (uint8_t*)block;
uint8_t *pke_ptr = (uint8_t*)hashrec.pke;
uint8_t *eapol_ptr = (uint8_t*)hashrec.eapol;

char pwstr[256];
char essidstr[256];

if(hcxrecord->essid_len > 32)
	return false;
if(pwlen > 64)
	return false;

hash[0] = 0;
hash[1] = 1;
hash[2] = 2;
hash[3] = 3;
memset(&block, 0, sizeof(block));

memset(&hashrec, 0, sizeof(hashrec));
memcpy(&hashrec.salt_buf, hcxrecord->essid, hcxrecord->essid_len);

if(((hcxrecord->keyver & 0x3) == 1) || ((hcxrecord->keyver & 0x3) == 2))
	{
	generatepke(hcxrecord, pke_ptr);
	}
else if((hcxrecord->keyver & 0x3) == 3)
	{
	pke_ptr[0] = 1;
	pke_ptr[1] = 0;
	pke_ptr[100] = 0x80;
	pke_ptr[101] = 1;

	generatepkeprf(hcxrecord, pke_ptr +2);
	}
else
	{
	return false;
	}

for (i = 0; i < 32; i++)
	{
	hashrec.pke[i] = byte_swap_32(hashrec.pke[i]);
	}

memcpy(eapol_ptr, hcxrecord->eapol, hcxrecord->eapol_len);
memset(eapol_ptr + hcxrecord->eapol_len, 0, (256 +64) -hcxrecord->eapol_len);
eapol_ptr[hcxrecord->eapol_len] = 0x80;

memcpy (&hashrec.keymic, hcxrecord->keymic, 16);

if(hcxrecord->keyver == 1)
	{
	// nothing to do
	}
else if(hcxrecord->keyver == 2)
	{
	hashrec.keymic[0] = byte_swap_32(hashrec.keymic[0]);
	hashrec.keymic[1] = byte_swap_32(hashrec.keymic[1]);
	hashrec.keymic[2] = byte_swap_32(hashrec.keymic[2]);
	hashrec.keymic[3] = byte_swap_32(hashrec.keymic[3]);
	for(i = 0; i < 64; i++)
		{
		hashrec.eapol[i] = byte_swap_32 (hashrec.eapol[i]);
		}
	}
else if (hcxrecord->keyver == 3)
	{
	// nothing to do
	}

for(i = 0; i < 16; i++)
	block[i] = hashrec.salt_buf[i];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.pke[i +0];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.pke[i +16];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +0];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +16];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +32];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i + 48];
md5_64 (block, hash);

for(i = 0; i < 6; i++)
	block_ptr[i +0] = hcxrecord->mac_ap.addr[i];
for(i = 0; i < 6; i++)
	block_ptr[i +6] = hcxrecord->mac_sta.addr[i];
md5_64 (block, hash);

for(i = 0; i < 32; i++)
	block_ptr[i +0] = hcxrecord->nonce_ap[i];
for(i = 0; i < 32; i++)
	block_ptr[i +32] = hcxrecord->nonce_sta[i];
md5_64 (block, hash);

block[0] = hashrec.keymic[0];
block[1] = hashrec.keymic[1];
block[2] = hashrec.keymic[2];
block[3] = hashrec.keymic[3];
md5_64 (block, hash);

memset(out, 0, 1024);
memset(&pwstr, 0, 256);
memset(&essidstr, 0, 256);

if(need_hexify(hcxrecord->essid, hcxrecord->essid_len) == true)
	{
	do_full_hexify(hcxrecord->essid, hcxrecord->essid_len, (uint8_t*)essidstr);
	}
else
	{
	memcpy(&essidstr, hcxrecord->essid, hcxrecord->essid_len);
	}

if((pwlen > 0) && (pwlen < 65))
	{
	if(need_hexify(password, pwlen) == true)
		{
		do_full_hexify(password, pwlen, (uint8_t*)pwstr);
		}
	else
		{
		memcpy(&pwstr, password, pwlen);
		}
	sprintf(out, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s:%s",
	hash[0], hash[1], hash[2], hash[3],
	hcxrecord->mac_ap.addr[0], hcxrecord->mac_ap.addr[1], hcxrecord->mac_ap.addr[2], hcxrecord->mac_ap.addr[3], hcxrecord->mac_ap.addr[4], hcxrecord->mac_ap.addr[5],
	hcxrecord->mac_sta.addr[0], hcxrecord->mac_sta.addr[1], hcxrecord->mac_sta.addr[2], hcxrecord->mac_sta.addr[3], hcxrecord->mac_sta.addr[4], hcxrecord->mac_sta.addr[5],
	essidstr, pwstr);
	}

else
	{
	sprintf(out, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
	hash[0], hash[1], hash[2], hash[3],
	hcxrecord->mac_ap.addr[0], hcxrecord->mac_ap.addr[1], hcxrecord->mac_ap.addr[2], hcxrecord->mac_ap.addr[3], hcxrecord->mac_ap.addr[4], hcxrecord->mac_ap.addr[5],
	hcxrecord->mac_sta.addr[0], hcxrecord->mac_sta.addr[1], hcxrecord->mac_sta.addr[2], hcxrecord->mac_sta.addr[3], hcxrecord->mac_sta.addr[4], hcxrecord->mac_sta.addr[5],
	essidstr);
	}

return true;
}

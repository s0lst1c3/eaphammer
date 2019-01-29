bool wpatesthash(hcx_t *zeigerhcx, uint8_t *pmk);

/*===========================================================================*/
bool wpatesthash(hcx_t *zeigerhcx, uint8_t *pmk)
{
int p;
uint8_t pkedata[102] = { 0 };
uint8_t pkedata_prf[2 + 98 + 2] = { 0 };
uint8_t ptk[128] = { 0 };
uint8_t mic[16] = { 0 };

memset(&pkedata, 0, sizeof(mic));
if(zeigerhcx->keyver == 1)
	{
	generatepke(zeigerhcx, pkedata);
	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
		}
	HMAC(EVP_md5(), &ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
	}

else if(zeigerhcx->keyver == 2)
	{
	generatepke(zeigerhcx, pkedata);
	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
		}
	HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
	}

else if(zeigerhcx->keyver == 3)
	{
	generatepkeprf(zeigerhcx, pkedata);
	pkedata_prf[0] = 1;
	pkedata_prf[1] = 0;
	memcpy (pkedata_prf + 2, pkedata, 98);
	pkedata_prf[100] = 0x80;
	pkedata_prf[101] = 1;
	HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
	}
if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
	return true;
return false;
}
/*===========================================================================*/

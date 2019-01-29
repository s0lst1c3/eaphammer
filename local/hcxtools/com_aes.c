int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac);

/*===========================================================================*/
static int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	CMAC_CTX *ctx;
	int ret = -1;
	size_t outlen, i;

	ctx = CMAC_CTX_new();
	if (ctx == NULL)
		return -1;

	if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL))
		goto fail;
	for (i = 0; i < num_elem; i++) {
		if (!CMAC_Update(ctx, addr[i], len[i]))
			goto fail;
	}
	if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16)
		goto fail;

	ret = 0;
fail:
	CMAC_CTX_free(ctx);
	return ret;
}
/*===========================================================================*/
int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/

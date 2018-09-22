#ifndef SHA1_H
#define SHA1_H

#define SHA1_MAC_LEN 20
typedef unsigned long u32;

typedef struct {
	u32 state[5];
	u32 count[2];
	unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX * context);
void SHA1Update(SHA1_CTX * context, unsigned char *data, u32 len);
void SHA1Final(unsigned char digest[20], SHA1_CTX * context);
void SHA1Transform(u32 state[5], unsigned char buffer[64]);

#endif				/* SHA1_H */

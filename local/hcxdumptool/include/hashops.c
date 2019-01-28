#include "hashops.h"

/*===========================================================================*/
uint32_t fcscrc32check(const uint8_t *buffer, uint32_t bufferlen)
{
uint32_t crc = 0xFFFFFFFF;
uint32_t p;

for(p = 0; p < bufferlen; ++p)
	{
	crc = crc32table[(crc ^buffer[p]) & 0xff] ^(crc >> 8);
	}
return ~crc;
}
/*===========================================================================*/

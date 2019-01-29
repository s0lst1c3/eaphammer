#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

#define PW_MAX 64

/*===========================================================================*/
uint32_t rotl32(uint32_t a, uint32_t n)
{
return((a << n) | (a >> (32 - n)));
}
/*===========================================================================*/
uint64_t rotl64(uint64_t a, uint64_t n)
{
return ((a << n) | (a >> (64 - n)));
}
/*===========================================================================*/
uint32_t rotr32(uint32_t a, uint32_t n)
{
return ((a >> n) | (a << (32 - n)));
}
/*===========================================================================*/
uint64_t rotr64(uint64_t a, uint64_t n)
{
return ((a >> n) | (a << (64 - n)));
}
/*===========================================================================*/
uint16_t byte_swap_16 (uint16_t n)
{
return (n & 0xff00) >> 8 | (n & 0x00ff) << 8;
}
/*===========================================================================*/
uint32_t byte_swap_32(uint32_t n)
{
#if defined (__clang__) || defined (__GNUC__)
return __builtin_bswap32 (n);
#else
return(n & 0xff000000) >> 24 | (n & 0x00ff0000) >> 8
      | (n & 0x0000ff00) << 8 | (n & 0x000000ff) << 24;
#endif
}
/*===========================================================================*/
uint64_t byte_swap_64(uint64_t n)
{
#if defined (__clang__) || defined (__GNUC__)
return __builtin_bswap64 (n);
#else
return (n & 0xff00000000000000ULL) >> 56
       | (n & 0x00ff000000000000ULL) >> 40
       | (n & 0x0000ff0000000000ULL) >> 24
       | (n & 0x000000ff00000000ULL) >>  8
       | (n & 0x00000000ff000000ULL) <<  8
       | (n & 0x0000000000ff0000ULL) << 24
       | (n & 0x000000000000ff00ULL) << 40
       | (n & 0x00000000000000ffULL) << 56;
#endif
}
/*===========================================================================*/
bool hexstr2bin(const char *str, uint8_t *bytes, size_t blen)
{
size_t c;
uint8_t pos;
uint8_t idx0;
uint8_t idx1;

const uint8_t hashmap[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

for(c = 0; c < blen; c++)
	{
	if(str[c] < '0')
		return false;
	if(str[c] > 'f')
		return false;
	if((str[c] > '9') && (str[c] < 'A'))
		return false;
	if((str[c] > 'F') && (str[c] < 'a'))
		return false;
	}

memset(bytes, 0, blen);
for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
return true;
}
/*===========================================================================*/
void uint8t2hex_lower(uint8_t v, uint8_t hex[2])
{
const uint8_t tbl[0x10] =
{
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

hex[1] = tbl[(v >> 0) &0xf];
hex[0] = tbl[(v >> 4) &0xf];
return;
}
/*===========================================================================*/
void do_hexify (uint8_t *buf, int len, uint8_t *out)
{
int i, j;
int max_len = (len >= PW_MAX) ? PW_MAX : len;
for(i = max_len - 1, j = i * 2; i >= 0; i -= 1, j -= 2)
	{
	uint8t2hex_lower(buf[i], out + j);
	}
out[max_len *2] = 0;
return;
}
/*===========================================================================*/
void do_full_hexify (uint8_t *buf, int len, uint8_t *out)
{
int i, j;
int max_len = (len >= PW_MAX) ? PW_MAX : len;
out[0] = '$';
out[1] = 'H';
out[2] = 'E';
out[3] = 'X';
out[4] = '[';
out += 5;
for (i = max_len - 1, j = i * 2; i >= 0; i -= 1, j -= 2)
	{
	uint8t2hex_lower(buf[i], out + j);
	}
out[max_len *2] = ']';
out[max_len *2 +1] = 0;
return;
}
/*===========================================================================*/
uint8_t hex_convert(uint8_t c)
{
return (c & 0xf) + (c >> 6) * 9;
}
/*===========================================================================*/
uint8_t hex2uint8t(uint8_t hex[2])
{
uint8_t v = 0;
v |= ((uint8_t)hex_convert(hex[1]) << 0);
v |= ((uint8_t)hex_convert(hex[0]) << 4);
return (v);
}
/*===========================================================================*/
bool is_valid_hex_char(uint8_t c)
{
if((c >= '0') && (c <= '9')) return true;
if((c >= 'A') && (c <= 'F')) return true;
if((c >= 'a') && (c <= 'f')) return true;
return false;
}
/*===========================================================================*/
bool is_valid_hex_string(uint8_t *s, int len)
{
int i;
if((len %2) != 0)
	return false;
for(i = 0; i < len; i++)
	if (is_valid_hex_char(s[i]) == false) return false;
return true;
}
/*===========================================================================*/
int do_unhexify(uint8_t *in_buf, int in_len, uint8_t *out_buf, int out_size)
{
int i, j;
uint8_t c;
for(i = 0, j = 5; j < in_len -1; i += 1, j += 2)
	{
	c = hex2uint8t(&in_buf[j]);
	out_buf[i] = c;
	}
memset(out_buf + i, 0, out_size -i);
return (i);
}
/*===========================================================================*/
bool is_hexify(uint8_t *in_buf, int len)
{
if(len < 6) return false; // $HEX[] = 6
if(in_buf[0]       != '$') return false;
if(in_buf[1]       != 'H') return false;
if(in_buf[2]       != 'E') return false;
if(in_buf[3]       != 'X') return false;
if(in_buf[4]       != '[') return false;
if(in_buf[len - 1] != ']') return false;
if(is_valid_hex_string(in_buf +5, len -6) == false) return false;
return true;
}
/*===========================================================================*/
bool is_printable_ascii (uint8_t *in_buf, int len)
{
int i;
for(i = 0; i < len; i++)
	{
	if(in_buf[i] < 0x20) return false;
	if(in_buf[i] > 0x7e) return false;
	if(in_buf[i] == ':') return false;
	}
return true;
}
/*===========================================================================*/
bool need_hexify(uint8_t *in_buf, int len)
{
if(is_printable_ascii(in_buf, len) == false)
	return true;
return false;
}
/*===========================================================================*/
int mystrlen(uint8_t *in_buf)
{
int c = 0;
while(in_buf[c] != 0)
	c++;
return c;
}
/*===========================================================================*/
int countdelimiter(uint8_t *in_buf, char delimiter)
{
int c = 0;
int d = 0;
while(in_buf[c] != 0)
	{
	if(in_buf[c] == delimiter)
		d++;
	c++;
	}
return d;
}
/*===========================================================================*/
int getdelimiterpos(uint8_t *in_buf, char delimiter)
{
int c = 0;
while(in_buf[c] != 0)
	{
	if(in_buf[c] == delimiter)
		return c;
	c++;
	}
return c;
}
/*===========================================================================*/

#define MD5_F(x,y,z)    ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x,y,z)    ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD5_I(x,y,z)    ((y) ^ ((x) | ~(z)))
#define MD5_Fo(x,y,z)   (MD5_F((x), (y), (z)))
#define MD5_Go(x,y,z)   (MD5_G((x), (y), (z)))

#define MD5_STEP_S(f,a,b,c,d,x,K,s) \
{                                   \
  a += K;                           \
  a += x;                           \
  a += f (b, c, d);                 \
  a  = rotl32_S (a, s);             \
  a += b;                           \
}

#define MD5_STEP(f,a,b,c,d,x,K,s)   \
{                                   \
  a += K;                           \
  a += x;                           \
  a += f (b, c, d);                 \
  a  = rotl32 (a, s);               \
  a += b;                           \
}

#define MD5_STEP0(f,a,b,c,d,K,s)    \
{                                   \
  a += K;                           \
  a += f (b, c, d);                 \
  a  = rotl32 (a, s);               \
  a += b;                           \
}


typedef enum md5_constants
{
  MD5M_A=0x67452301,
  MD5M_B=0xefcdab89,
  MD5M_C=0x98badcfe,
  MD5M_D=0x10325476,

  MD5S00=7,
  MD5S01=12,
  MD5S02=17,
  MD5S03=22,
  MD5S10=5,
  MD5S11=9,
  MD5S12=14,
  MD5S13=20,
  MD5S20=4,
  MD5S21=11,
  MD5S22=16,
  MD5S23=23,
  MD5S30=6,
  MD5S31=10,
  MD5S32=15,
  MD5S33=21,

  MD5C00=0xd76aa478,
  MD5C01=0xe8c7b756,
  MD5C02=0x242070db,
  MD5C03=0xc1bdceee,
  MD5C04=0xf57c0faf,
  MD5C05=0x4787c62a,
  MD5C06=0xa8304613,
  MD5C07=0xfd469501,
  MD5C08=0x698098d8,
  MD5C09=0x8b44f7af,
  MD5C0a=0xffff5bb1,
  MD5C0b=0x895cd7be,
  MD5C0c=0x6b901122,
  MD5C0d=0xfd987193,
  MD5C0e=0xa679438e,
  MD5C0f=0x49b40821,
  MD5C10=0xf61e2562,
  MD5C11=0xc040b340,
  MD5C12=0x265e5a51,
  MD5C13=0xe9b6c7aa,
  MD5C14=0xd62f105d,
  MD5C15=0x02441453,
  MD5C16=0xd8a1e681,
  MD5C17=0xe7d3fbc8,
  MD5C18=0x21e1cde6,
  MD5C19=0xc33707d6,
  MD5C1a=0xf4d50d87,
  MD5C1b=0x455a14ed,
  MD5C1c=0xa9e3e905,
  MD5C1d=0xfcefa3f8,
  MD5C1e=0x676f02d9,
  MD5C1f=0x8d2a4c8a,
  MD5C20=0xfffa3942,
  MD5C21=0x8771f681,
  MD5C22=0x6d9d6122,
  MD5C23=0xfde5380c,
  MD5C24=0xa4beea44,
  MD5C25=0x4bdecfa9,
  MD5C26=0xf6bb4b60,
  MD5C27=0xbebfbc70,
  MD5C28=0x289b7ec6,
  MD5C29=0xeaa127fa,
  MD5C2a=0xd4ef3085,
  MD5C2b=0x04881d05,
  MD5C2c=0xd9d4d039,
  MD5C2d=0xe6db99e5,
  MD5C2e=0x1fa27cf8,
  MD5C2f=0xc4ac5665,
  MD5C30=0xf4292244,
  MD5C31=0x432aff97,
  MD5C32=0xab9423a7,
  MD5C33=0xfc93a039,
  MD5C34=0x655b59c3,
  MD5C35=0x8f0ccc92,
  MD5C36=0xffeff47d,
  MD5C37=0x85845dd1,
  MD5C38=0x6fa87e4f,
  MD5C39=0xfe2ce6e0,
  MD5C3a=0xa3014314,
  MD5C3b=0x4e0811a1,
  MD5C3c=0xf7537e82,
  MD5C3d=0xbd3af235,
  MD5C3e=0x2ad7d2bb,
  MD5C3f=0xeb86d391u

} md5_constants_t;
/*===========================================================================*/

void md5_64 (uint32_t block[16], uint32_t digest[4]);

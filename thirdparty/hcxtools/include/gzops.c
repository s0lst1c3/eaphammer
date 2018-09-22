#include <zlib.h>
#include "gzops.h"

/*===========================================================================*/
bool testgzipfile(char *pcapinname)
{
int pcapr_fd;
uint32_t magicnumber;

pcapr_fd = open(pcapinname, O_RDONLY);
if(pcapr_fd == -1)
	{
	return false;
	}
magicnumber = getmagicnumber(pcapr_fd);
close(pcapr_fd);

if((magicnumber &0xffff) != GZIPMAGICNUMBER)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
bool decompressgz(char *gzname, char *tmpoutname)
{
FILE *fhin = NULL;
FILE *fhout = NULL;
z_stream strm;
unsigned char in[CHUNK];
unsigned char out[CHUNK];

memset(&strm, 0, sizeof (strm));
strm.zalloc = Z_NULL;
strm.zfree = Z_NULL;
strm.opaque = Z_NULL;
strm.next_in = in;
strm.avail_in = 0;

inflateInit2(& strm, windowBits | ENABLE_ZLIB_GZIP);
printf("decompressing %s to %s\n", basename(gzname), tmpoutname);
fhin = fopen (gzname, "rb");
if(fhin == NULL)
	{
	printf("failed to decompress%s\n", gzname);
	return false;
	}

fhout = fopen (tmpoutname, "wb");
if(fhin == NULL)
	{
	printf("failed to decompress%s\n", tmpoutname);
	return false;
	}

while(1)
	{
	int bytes_read;
	int zlib_status;
	bytes_read = fread (in, sizeof(char), sizeof(in), fhin);
	if(ferror(fhin))
		{
		inflateEnd (& strm);
		printf("failed to decompress %s\n", gzname);
		fclose(fhout);
		fclose(fhin);
		return false;
		}
	strm.avail_in = bytes_read;
	strm.next_in = in;

	do
		{
		unsigned have;
		strm.avail_out = CHUNK;
		strm.next_out = out;
		zlib_status = inflate(&strm, Z_NO_FLUSH);
		switch (zlib_status)
			{
			case Z_OK:
			case Z_STREAM_END:
			case Z_BUF_ERROR:
			break;
			default:
			inflateEnd (& strm);
			printf("failed to decompress %s\n", gzname);
			return false;
			}

		have = CHUNK - strm.avail_out;
		fwrite(out, sizeof (unsigned char), have, fhout);
		}
	while(strm.avail_out == 0);
	if(feof(fhin))
		{
		inflateEnd(&strm);
		break;
		}
	}
fclose(fhout);
fclose(fhin);
return true;
}
/*===========================================================================*/

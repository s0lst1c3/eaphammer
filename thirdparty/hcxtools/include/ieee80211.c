#include "ieee80211.h"

/*===========================================================================*/
int getkeyinfo(uint16_t ki)
{
if(ki & WPA_KEY_INFO_ACK)
	{
	if(ki & WPA_KEY_INFO_INSTALL)
		{
		/* handshake 3 */
		return 3;

		}
	else
		{
		/* handshake 1 */
		return 1;
		}
	}
else
	{
	if(ki & WPA_KEY_INFO_SECURE)
		{
		/* handshake 4 */
		return 4;

		}
	else
		{
		/* handshake 2 */
		return 2;
		}
	}
return 0;
}
/*===========================================================================*/

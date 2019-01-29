#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wiringPi.h>

/*===========================================================================*/
int main()
{
int ret;
if(wiringPiSetup() == -1)
	{
	puts("wiringPi failed!");
	system("poweroff");
	}

pinMode(0, OUTPUT);
pinMode(7, INPUT);

while(1)
	{
	digitalWrite(0, HIGH);
	delay (250);
	digitalWrite(0, LOW);
	delay (250);
	digitalWrite(0, HIGH);
	delay (250);
	digitalWrite(0, LOW);
	delay (250);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		ret = system("poweroff");
		if(ret != 0)
			{
			puts("poweroff failed!");
			exit(EXIT_FAILURE);
			}
		}
	sleep(10);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

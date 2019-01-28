PREFIX		?=/usr/local
INSTALLDIR	= $(DESTDIR)$(PREFIX)/bin

HOSTOS		:= $(shell uname -s)
GPIOSUPPORT=off

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra
CFLAGS 		+= -std=gnu99
INSTFLAGS	= -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(GPIOSUPPORT), on)
CFLAGS	+= -DDOGPIOSUPPORT
LDFLAGS	+= -lwiringPi
endif


all: build

build:
ifeq ($(GPIOSUPPORT), on)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o hcxpioff hcxpioff.c $(LDFLAGS)
endif
ifeq ($(HOSTOS), Linux)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o hcxdumptool hcxdumptool.c -lpthread $(LDFLAGS)
endif


install: build
ifeq ($(GPIOSUPPORT), on)
	install $(INSTFLAGS) hcxpioff $(INSTALLDIR)/hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	install $(INSTFLAGS) hcxdumptool $(INSTALLDIR)/hcxdumptool
endif

ifeq ($(GPIOSUPPORT), on)
	rm -f hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f hcxdumptool
endif
	rm -f *.o *~


clean:
ifeq ($(GPIOSUPPORT), on)
	rm -f hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f hcxdumptool
endif
	rm -f *.o *~


uninstall:
ifeq ($(GPIOSUPPORT), on)
	rm -f $(INSTALLDIR)/hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f $(INSTALLDIR)/hcxdumptool
endif

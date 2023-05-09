CC=gcc
CFLAGS= -g
LFLAGS= -lpcap

MKDIR=/bin/mkdir
INSTALL=/usr/bin/install

SOURCES  := $(wildcard *.c)
INCLUDES := $(wildcard *.h)
OBJECTS  := $(SOURCES:%.c=%.o)

LISTENER_SOURCES := listener.c
SENDER_SOURCES   := sender.c
COMMON_SOURCES   := dbg-util.c util.c

LISTENER_OBJECTS := $(LISTENER_SOURCES:.c=.o)
SENDER_OBJECTS   := $(SENDER_SOURCES:.c=.o)
COMMON_OBJECTS   := $(COMMON_SOURCES:.c=.o)

rm       = rm -f

LISTEN_EU_IPV4 = "95.179.253.254"
LISTEN_EU_IPV6 = "2001:19f0:6c01:26e8:5400:2ff:fed7:c0cc"
LISTEN_EU_INTERFACE = "ens3"
RCV_DATA_EU = "95.179.253.254:25002"
SEND_EU_IPV4 = "95.179.253.254"
SEND_EU_IPV6 = "2001:19f0:6c01:26e8:5400:2ff:fed7:c0cc"
SEND_EU_INTERFACE = "ens3"
MYMAC_EU = "56:00:02:d7:c0:cc"
GW_MAC_EU_V4 = "fe:00:02:d7:c0:cc"
GW_MAC_EU_V6 = "fe:00:02:d7:c0:cc"


LISTEN_AM_IPV4 = "149.28.91.227"
LISTEN_AM_IPV6 = "2001:19f0:6001:4c0c:5400:3ff:fe34:45ba"
LISTEN_AM_INTERFACE = "ens3"
RCV_DATA_AM = "149.28.91.227:25002"
SEND_AM_IPV4 = "149.28.91.227"
SEND_AM_IPV6 = "2001:19f0:6001:4c0c:5400:3ff:fe34:45ba"
SEND_AM_INTERFACE = "ens3"

LISTEN_AP_IPV4 = "139.180.140.125"
LISTEN_AP_IPV6 = "2001:19f0:4400:505a:5400:2ff:fed4:2cb3"
LISTEN_AP_INTERFACE = "ens3"
RCV_DATA_AP = "139.180.140.125:25002"
SEND_AP_IPV4 = "139.180.140.125"
SEND_AP_IPV6 = "2001:19f0:4400:505a:5400:2ff:fed4:2cb3"
SEND_AP_INTERFACE = "ens3"

LISTEN_IN_IPV4 = "65.20.81.159"
LISTEN_IN_IPV6 = "2401:c080:2400:1f43:5400:4ff:fe3f:afb9"
LISTEN_IN_INTERFACE = "enp1s0"
RCV_DATA_IN = "65.20.81.159:25002"
SEND_IN_IPV4 = "65.20.81.159"
SEND_IN_IPV6 = "2401:c080:2400:1f43:5400:4ff:fe3f:afb9"
SEND_IN_INTERFACE = "enp1s0"

LISTEN_TARCUTTA_IPV4 = "203.133.248.122"
LISTEN_TARCUTTA_IPV6 = "2401:2000:6660::122"
LISTEN_TARCUTTA_INTERFACE = "eno1"
RCV_DATA_TARCUTTA = "203.133.248.122:25002"
SEND_TARCUTTA_IPV4 = "203.133.248.122"
SEND_TARCUTTA_IPV6 = "2401:2000:6660::122"
SEND_TARCUTTA_INTERFACE = "eno1"
MYMAC_TARCUTTA = ""
GW_MAC_TARCUTTA_V4 = ""
GW_MAC_TARCUTTA_V6 = ""

# simple logic to force make to be told what host to make for
HOST=

ifndef HOST
$(error HOST must be set to one of {eu, am ap, in, tarcutta} eg by calling make HOST=<value> for Vultr hosts RPKI*)
endif

# Pick the right IP Addresses
LISTEN_IPV4 = LISTEN_$(HOST)_IPV4
LISTEN_IPV6 = LISTEN_$(HOST)_IPV6
LISTEN_IFACE = LISTEN_$(HOST)_INTERFACE
RCV_DATA = RCV_DATA_$(HOST)
SEND_IPV4 = SEND_$(HOST)_IPV4
SEND_IPV6 = SEND_$(HOST)_IPV6
SEND_IFACE = SEND_$(HOST)_INTERFACE
MYMAC = MYMAC_$(HOST)
GW_MAC_V4 = GW_MAC_$(HOST)_V4
GW_MAC_V6 = GW_MAC_$(HOST)_V6

$(info $$COMMON_SOURCES [$(COMMON_SOURCES)])
$(info $$SENDER_SOURCES [$(SENDER_SOURCES)])
$(info $$LISTENER_SOURCES [$(LISTENER_SOURCES)])

$(info $$COMMON_OBJECTS [$(COMMON_OBJECTS)])
$(info $$SENDER_OBJECTS [$(SENDER_OBJECTS)])
$(info $$LISTENER_OBJECTS [$(LISTENER_OBJECTS)])

all: listener sender systemd

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

listener: $(LISTENER_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(LISTENER_OBJECTS) $(COMMON_OBJECTS) $(LFLAGS) -o $@

sender: $(SENDER_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(SENDER_OBJECTS) $(COMMON_OBJECTS) $(LFLAGS) -o $@

systemd:
	sed -e "s/@V4@/$(${LISTEN_IPV4})/" -e "s/@V6@/$($(LISTEN_IPV6))/" -e "s/@INT@/$($(LISTEN_IFACE))/" < etc.systemd.system.yarrp-listener.service.tmpl >etc.systemd.system.yarrp-listener.service
	sed -e "s/@V4@/$(${SEND_IPV4})/" -e "s/@V6@/$($(SEND_IPV6))/" -e "s/@INT@/$($(SEND_IFACE))/" -e "s/@RCV_DATA@/$($(RCV_DATA))/" \
			-e "s/@MYMAC@/$(${MYMAC})/"	-e "s/@GW_MAC_V4@/$(${GW_MAC_V4})/" 	-e "s/@GW_MAC_V6@/$(${GW_MAC_V6})/" \
			< etc.systemd.system.yarrp-sender.service.tmpl >etc.systemd.system.yarrp-sender.service

.PHONY: clean
clean:
	$(rm) sender listener
	$(rm) $(OBJECTS)
	@echo "Object file cleanup complete!"

.PHONY: remove
distclean: clean
	$(rm) listener sender
	@echo "Executable removed!"

install: all
	$(INSTALL) listener /usr/local/bin
	$(INSTALL) sender /usr/local/bin
	mkdir -p /usr/local/lib/systemd/system
	$(INSTALL) -m 644 etc.systemd.system.yarrp-sender.service /usr/local/lib/systemd/system/yarrp-sender.service
	$(INSTALL) -m 644 etc.systemd.system.yarrp-listener.service /usr/local/lib/systemd/system/yarrp-listener.service
	$(MKDIR) -p -m777  /tmp/pinger/
	
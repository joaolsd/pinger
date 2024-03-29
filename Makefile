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

HOST=$(shell hostname -s)

# RPKI2: Singapore, AP
# RPKI3: Frankfurt, EU
# RPKI4: Los Angeles, AM
# RPKI5: Mumbai, IN

LISTEN_rpki2_IPV4 = "203.10.61.2"
LISTEN_rpki2_IPV6 = "2001:19f0:4400:505a:5400:2ff:fed4:2cb3"
LISTEN_rpki2_INTERFACE = "ens3"
RCV_DATA_rpki2 = "139.180.140.125:25002"
SEND_rpki2_IPV4 = "203.10.61.2"
SEND_rpki2_IPV6 = "2001:19f0:4400:505a:5400:2ff:fed4:2cb3"
SEND_rpki2_INTERFACE = "ens3"
MY_MAC_rpki2 = "56:00:02:d4:2c:b3"
GW_MAC_rpki2_V4 = "fe:00:02:d4:2c:b3"
GW_MAC_rpki2_V6 = "fe:00:02:d4:2c:b3"

LISTEN_rpki3_IPV4 = "203.10.61.2"
LISTEN_rpki3_IPV6 = "2001:19f0:6c01:26e8:5400:2ff:fed7:c0cc"
LISTEN_rpki3_INTERFACE = "ens3"
RCV_DATA_rpki3 = "95.179.253.254:25002"
SEND_rpki3_IPV4 = "203.10.61.2"
SEND_rpki3_IPV6 = "2001:19f0:6c01:26e8:5400:2ff:fed7:c0cc"
SEND_rpki3_INTERFACE = "ens3"
MY_MAC_rpki3 = "56:00:02:d7:c0:cc"
GW_MAC_rpki3_V4 = "fe:00:02:d7:c0:cc"
GW_MAC_rpki3_V6 = "fe:00:02:d7:c0:cc"

LISTEN_rpki4_IPV4 = "203.10.61.2"
LISTEN_rpki4_IPV6 = "2001:19f0:6001:4c0c:5400:3ff:fe34:45ba"
LISTEN_rpki4_INTERFACE = "ens3"
RCV_DATA_rpki4 = "149.28.91.227:25002"
SEND_rpki4_IPV4 = "203.10.61.2"
SEND_rpki4_IPV6 = "2001:19f0:6001:4c0c:5400:3ff:fe34:45ba"
SEND_rpki4_INTERFACE = "ens3"
MY_MAC_rpki4 = "56:00:03:34:45:ba"
GW_MAC_rpki4_V4 = "92:9f:29:e2:45:55"
GW_MAC_rpki4_V6 = "92:9f:29:e2:45:55"

LISTEN_rpki5_IPV4 = "203.10.61.2"
LISTEN_rpki5_IPV6 = "2401:c080:2400:1f43:5400:4ff:fe3f:afb9"
LISTEN_rpki5_INTERFACE = "enp1s0"
RCV_DATA_rpki5 = "65.20.81.159:25002"
SEND_rpki5_IPV4 = "203.10.61.2"
SEND_rpki5_IPV6 = "2401:c080:2400:1f43:5400:4ff:fe3f:afb9"
SEND_rpki5_INTERFACE = "enp1s0"
MY_MAC_rpki5 = "56:00:04:3f:af:b9"
GW_MAC_rpki5_V4 = "fe:00:04:3f:af:b9"
GW_MAC_rpki5_V6 = "fe:00:04:3f:af:b9"

LISTEN_TARCUTTA_IPV4 = "203.10.61.2"
LISTEN_TARCUTTA_IPV6 = "2401:2000:6660::122"
LISTEN_TARCUTTA_INTERFACE = "eno1"
RCV_DATA_TARCUTTA = "203.133.248.122:25002"
SEND_TARCUTTA_IPV4 = "203.10.61.2"
SEND_TARCUTTA_IPV6 = "2401:2000:6660::122"
SEND_TARCUTTA_INTERFACE = "eno1"
MY_MAC_TARCUTTA = "14:18:77:43:b9:b8"
GW_MAC_TARCUTTA_V4 = "00:00:0c:9f:f4:59"
GW_MAC_TARCUTTA_V6 = "00:05:73:a0:08:41"

LISTEN_HK_IPV4 = "172.31.47.23"
LISTEN_HK_IPV6 = "2406:da1e:a32:5a00:ba8b:c77:71d8:2bfe"
LISTEN_HK_INTERFACE = "ens5"
RCV_DATA_HK = "172.31.47.23:25002"
SEND_HK_IPV4 = "172.31.47.23"
SEND_HK_IPV6 = "2406:da1e:a32:5a00:ba8b:c77:71d8:2bfe"
SEND_HK_INTERFACE = "ens5"
MY_MAC_HK = "0e:9c:25:4b:fd:0e"
GW_MAC_HK_V4 = "0e:96:a0:22:32:1c"
GW_MAC_HK_V6 = "0e:96:a0:22:32:1c"

LISTEN_IN_IPV4 = "192.46.213.112"
LISTEN_IN_IPV6 = "2400:8904::f03c:92ff:feff:44e1"
LISTEN_IN_INTERFACE = "eth0"
RCV_DATA_IN = "192.46.213.112:25002"
SEND_IN_IPV4 = "192.46.213.112"
SEND_IN_IPV6 = "2400:8904::f03c:92ff:feff:44e1"
SEND_IN_INTERFACE = "eth0"
MY_MAC_IN = "f2:3c:92:ff:44:e1"
GW_MAC_IN_V4 = "00:00:5e:00:be:ef"
GW_MAC_IN_V6 = "00:00:5e:00:be:ef"

LISTEN_SCO_IPV4 = "137.50.17.110"
LISTEN_SCO_IPV6 = "2400:8904::f03c:92ff:feff:44e1"
LISTEN_SCO_INTERFACE = "eth0"
RCV_DATA_SCO = "137.50.17.110:25002"
SEND_SCO_IPV4 = "137.50.17.110"
SEND_SCO_IPV6 = "2400:8904::f03c:92ff:feff:44e1"
SEND_SCO_INTERFACE = "eth0"
MY_MAC_SCO = "62:ed:9b:3e:3b:30"
GW_MAC_SCO_V4 = "00:1b:21:bd:ea:04"
GW_MAC_SCO_V6 = "00:1b:21:bd:ea:04"

# Pick the right IP Addresses
LISTEN_IPV4 = LISTEN_$(HOST)_IPV4
LISTEN_IPV6 = LISTEN_$(HOST)_IPV6
LISTEN_IFACE = LISTEN_$(HOST)_INTERFACE
RCV_DATA = RCV_DATA_$(HOST)
SEND_IPV4 = SEND_$(HOST)_IPV4
SEND_IPV6 = SEND_$(HOST)_IPV6
SEND_IFACE = SEND_$(HOST)_INTERFACE
MY_MAC = MY_MAC_$(HOST)
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
			-e "s/@MY_MAC@/$(${MY_MAC})/"	-e "s/@GW_MAC_V4@/$(${GW_MAC_V4})/" 	-e "s/@GW_MAC_V6@/$(${GW_MAC_V6})/" \
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
	
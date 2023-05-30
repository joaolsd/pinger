#!/usr/bin/env bash

./listener  -i eno1 -k  203.133.248.122 -l 2401:2000:6660::122  -o yarrp-noeh.log &
PID=$!
./sender -f ./yarrp-noeh.csv -4 203.133.248.122 -6 2401:2000:6660::122 -i eno1 -a 14:18:77:43:b9:b8 -b 00:00:0c:9f:f4:59 -c 00:05:73:a0:08:41
kill $PID
HOSTNAME=/bin/hostname

for size in 8 16 32 64 128
do
  ./listener  -i eno1 -k  203.133.248.122 -l 2401:2000:6660::122  -o yarrp-$HOSTNAME-hbh$size.log &
  LISTEN_PID=$!
  tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i eno1  'dst port 443 or  icmp6[0]==3' &
  TCPDUMP_PID=$!
  ./sender -f ./yarrp-hbh$size.csv -4 203.133.248.122 -6 2401:2000:6660::122 -i eno1 -a 14:18:77:43:b9:b8 -b 00:00:0c:9f:f4:59 -c 00:05:73:a0:08:41
  kill $LISTEN_PID
  kill $TCPDUMP_PID
done

for size in 8 16 32 64 128
do
  ./listener  -i eno1 -k  203.133.248.122 -l 2401:2000:6660::122  -o yarrp-$HOSTNAME-dst$size.log &
  LISTEN_PID=$!
  tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i eno1  'dst port 443 or  icmp6[0]==3' &
  TCPDUMP_PID=$!
  ./sender -f ./yarrp-dst$size.csv -4 203.133.248.122 -6 2401:2000:6660::122 -i eno1 -a 14:18:77:43:b9:b8 -b 00:00:0c:9f:f4:59 -c 00:05:73:a0:08:41
  kill $LISTEN_PID
  kill $TCPDUMP_PID
done
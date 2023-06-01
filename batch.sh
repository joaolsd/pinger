#!/usr/bin/env bash

MY_IPV4=203.133.248.122
MY_IPV6=2401:2000:6660::122
MY_MAC=14:18:77:43:b9:b8
DFGW_V4_MAC=00:00:0c:9f:f4:59
DFGW_V6_MAC=00:05:73:a0:08:41
INT=eno1

HOSTNAME=$(/bin/hostname)
./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o yarrp-$HOSTNAME-noeh.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i eno1  'dst port 443 or  icmp6[0]==3' &
TCPDUMP_PID=$!
./sender -f ./yarrp-noeh.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
kill $LISTEN_PID
kill $TCPDUMP_PID

for size in 8 16 32 64 128
do
  sleep 2
  ./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o yarrp-$HOSTNAME-hbh$size.log &
  LISTEN_PID=$!
  tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i eno1  'dst port 443 or  icmp6[0]==3' &
  TCPDUMP_PID=$!
  ./sender -f ./yarrp-hbh$size.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
  kill $LISTEN_PID
  kill $TCPDUMP_PID
done

for size in 8 16 32 64 128
do
  sleep 2
  ./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6 -o yarrp-$HOSTNAME-dst$size.log &
  LISTEN_PID=$!
  tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i eno1  'dst port 443 or  icmp6[0]==3' &
  TCPDUMP_PID=$!
  ./sender -f ./yarrp-dst$size.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
  kill $LISTEN_PID
  kill $TCPDUMP_PID
done

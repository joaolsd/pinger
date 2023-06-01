#!/usr/bin/env bash

HOSTNAME=$(/bin/hostname -s)

source batch-$HOSTNAME-cfg.sh

./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o yarrp-$HOSTNAME-noeh.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-noeh.pcap -i $INT "src $MY_IPV6 and dst port 443 or  icmp6[0]==3" &
TCPDUMP_PID=$!
./sender -f ./yarrp-noeh.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
kill $LISTEN_PID
kill $TCPDUMP_PID

for size in 8 16 32 64 128
do
  sleep 2
  ./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o yarrp-$HOSTNAME-hbh$size.log &
  LISTEN_PID=$!
  tcpdump -nvvvv -w pkts-$HOSTNAME-hbh$size.pcap -i $INT "src $MY_IPV6 and dst port 443 or  icmp6[0]==3" &
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
  tcpdump -nvvvv -w pkts-$HOSTNAME-dst$size.pcap -i $INT "src $MY_IPV6 and dst port 443 or  icmp6[0]==3" &
  TCPDUMP_PID=$!
  ./sender -f ./yarrp-dst$size.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
  kill $LISTEN_PID
  kill $TCPDUMP_PID
done

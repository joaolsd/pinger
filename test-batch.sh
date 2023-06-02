#!/usr/bin/env bash

HOSTNAME=$(/bin/hostname -s)

source batch-$HOSTNAME-cfg.sh

./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o yarrp-$HOSTNAME-test.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-test.pcap -i $INT "src $MY_IPV6 and dst port 443 or  icmp6[0]==3" &
TCPDUMP_PID=$!
./sender -f ./test.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
sleep 3
kill $LISTEN_PID
kill $TCPDUMP_PID


#!/usr/bin/env bash

HOSTNAME=$(/bin/hostname -s)

source batch-$HOSTNAME-cfg.sh

./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o rpki4-$HOSTNAME-test.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-rpki4-test.pcap -i $INT "port 443 or icmp[0]==11 or icmp[0]==3" &
TCPDUMP_PID=$!
sleep 3
./sender -f ./rpki4.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
sleep 3
kill $LISTEN_PID
kill $TCPDUMP_PID


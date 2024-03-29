#!/usr/bin/env bash

HOSTNAME=$(/bin/hostname -s)

source batch-$HOSTNAME-cfg.sh

# Run "traceroute" for IPv4 addresses in file using the ROA valid source address
./listener  -i $INT -k $MY_IPV4 -l $MY_IPV6  -o rpki4-valid-$HOSTNAME-test.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-rpki4-valid.pcap -i $INT "port 443 or icmp[0]==11 or icmp[0]==3" &
TCPDUMP_PID=$!
sleep 3
./sender -s 1 -f ./rpki4.csv -i $INT -4 $MY_IPV4 -6 $MY_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
sleep 3
kill $LISTEN_PID
kill $TCPDUMP_PID

sleep 3

# Run "traceroute" for IPv4 addresses in file using the ROA **INVALID** source address
./listener  -i $INT -k $MY_INVALID_IPV4 -l $MY_INVALID_IPV6  -o rpki4-invalid-$HOSTNAME-test.log &
LISTEN_PID=$!
tcpdump -nvvvv -w pkts-$HOSTNAME-rpki4-invalid.pcap -i $INT "port 443 or icmp[0]==11 or icmp[0]==3" &
TCPDUMP_PID=$!
sleep 3
./sender -s 1 -f ./rpki4.csv -i $INT -4 $MY_INVALID_IPV4 -6 $MY_INVALID_IPV6 -a $MY_MAC -b $DFGW_V4_MAC -c $DFGW_V6_MAC
sleep 3
kill $LISTEN_PID
kill $TCPDUMP_PID

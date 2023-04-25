#ifndef UTIL_H
#define UTIL_H

#include "sender.h"

struct tr_conf {
	u_int8_t	first_ttl;	/* Set the first TTL or hop limit */
	u_int8_t	max_ttl;	/* Set the maximum TTL / hop limit */
	u_char		proto;		/* IP payload protocol to use */
	u_int8_t	nprobes;
	u_int16_t	port;		/* start udp dest port */
	int				waittime;	/* time to wait for a response */
	int				verbose;
	int 			debug;
	u_short		ident;
	char		 *source;
	char		 *if_name;
};

/*
 * Format of the data in a (udp) probe packet.
 */
struct packetdata {
	u_char seq;		/* sequence number of this packet */
	u_int8_t ttl;		/* ttl packet left with */
	u_char pad[2];
	u_int32_t sec;		/* time packet left */
	u_int32_t usec;
};

void  daemonise();

uint16_t checksum(uint16_t *buffer, int size);
uint16_t tcp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr);
uint16_t udp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr);
uint16_t icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr, uint8_t *payload, int payloadlen);
uint16_t crc16(uint16_t crc, uint8_t const *buffer, size_t len);


void ether_header(int IP_v, uint8_t *outpacket);

int build_probe4(struct tr_conf *conf, int seq, u_int8_t ttl, uint8_t *outpacket, struct probe *probe);
int build_probe6(struct tr_conf *conf, int seq, u_int8_t hops, uint8_t *outpacket, struct probe *probe);
void send_probe(struct tr_conf *conf, int sndsock, int seq, u_int8_t ttl, struct probe *probe, FILE *log_f);

#endif // UTIL_H
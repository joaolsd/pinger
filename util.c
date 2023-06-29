#include <stdio.h>
#include <stdint.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "dbg-util.h"
#include "sender.h"
#include "util.h"

#define ICMP_CODE 0;

#define ETH_HDRLEN 14
#define IP_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN 20
#define ICMP_HDRLEN 4  // ICMP header length for echo request, excludes data
#define ICMP6_HDRLEN 4  // ICMP header length for echo request, excludes data

u_int8_t icmp_type;

// uint8_t src_mac[] = {0x6a, 0x89, 0x86, 0xa8, 0xdb, 0xf7}; // for the mac mini UTM VM
// uint8_t dst_mac[] = {0x16, 0x98, 0x77, 0x25, 0xf5, 0x64}; //
// uint8_t dst_mac[] = {0xd8, 0x58, 0xd7, 0x00, 0x37, 0x1d}; // at home
// uint8_t src_mac[] = {0xf2, 0x3c, 0x91, 0xd5, 0x03, 0x95}; // for testbed-de
// uint8_t dst_mac[] = {0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x04}; // for testbed-de's gateway

uint8_t src_mac[6] = {0x56,0x00,0x02,0xd7,0xc0,0xcc}; // rpki3 (eu)
uint8_t dst_mac_v4[6] = {0xfe,0x00,0x02,0xd7,0xc0,0xcc}; // rpki3 (eu)
uint8_t dst_mac_v6[6] = {0xfe,0x00,0x02,0xd7,0xc0,0xcc}; // rpki3 (eu)

/***************************************************
 * Generic checksum
 * can be used for IP, UDP , TCP if the buffer is properly setup
 **************************************************/
uint16_t checksum(uint16_t *buffer, int size) {
  unsigned long cksum=0;
  while(size >1) {
    cksum += ntohs(*buffer++);
    size -= sizeof(uint16_t);
  }
  if(size) {
    cksum += *(uint8_t *)buffer;    	
  }
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >>16);
	
  return (uint16_t)(~cksum);
}

/***************************************************
// Build IPv6 ICMP pseudo-header and call checksum function
 **************************************************/
uint16_t icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr, uint8_t *payload, int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];

  // Copy source IP address
  memcpy(ptr, &iphdr->ip6_src.s6_addr, sizeof(iphdr->ip6_src.s6_addr));
  ptr += sizeof(iphdr->ip6_src);
  chksumlen += sizeof(iphdr->ip6_src);

  // Copy destination IP address
  memcpy(ptr, &iphdr->ip6_dst.s6_addr, sizeof(iphdr->ip6_dst.s6_addr));
  ptr += sizeof(iphdr->ip6_dst.s6_addr);
  chksumlen += sizeof(iphdr->ip6_dst.s6_addr);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (ICMP6_HDRLEN + payloadlen) / 256;
  ptr++;
  *ptr = (ICMP6_HDRLEN + payloadlen) % 256;
  ptr++;
  chksumlen += 4;

  // Copy zero field
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field
  memcpy(ptr, &iphdr->ip6_nxt, sizeof(iphdr->ip6_nxt));
  ptr += sizeof(iphdr->ip6_nxt);
  chksumlen += sizeof(iphdr->ip6_nxt);

  // Copy ICMPv6 type
  memcpy(ptr, &icmp6hdr->icmp6_type, sizeof (icmp6hdr->icmp6_type));
  ptr += sizeof(icmp6hdr->icmp6_type);
  chksumlen += sizeof(icmp6hdr->icmp6_type);

  // Copy ICMPv6 code
  memcpy(ptr, &icmp6hdr->icmp6_code, sizeof (icmp6hdr->icmp6_code));
  ptr += sizeof(icmp6hdr->icmp6_code);
  chksumlen += sizeof(icmp6hdr->icmp6_code);

  // Copy ICMPv6 ID
  memcpy(ptr, &icmp6hdr->icmp6_id, sizeof (icmp6hdr->icmp6_id));
  ptr += sizeof(icmp6hdr->icmp6_id);
  chksumlen += sizeof(icmp6hdr->icmp6_id);

  // Copy ICMPv6 sequence number
  memcpy(ptr, &icmp6hdr->icmp6_seq, sizeof(icmp6hdr->icmp6_seq));
  ptr += sizeof(icmp6hdr->icmp6_seq);
  chksumlen += sizeof(icmp6hdr->icmp6_seq);

  // Copy ICMPv6 checksum to buf (16 bits)
  // Zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy ICMPv6 payload to buf
  if (payload != NULL) {
    memcpy (ptr, payload, payloadlen * sizeof(uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;
  }

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
  }

  return checksum((uint16_t *) buf, chksumlen);
}

/***************************************************
 * tcp checksum
 * calculate the TCP checksum when over IPv4
 **************************************************/
uint16_t 
tcp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  int i  ;
 
  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if (len)  // Add the padding if the packet length is odd
    sum += *((uint8_t *)buf);
 
  // Add the pseudo-header
  for (i = 0 ; i <= 1 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 1 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_TCP);
  sum += htons(length);
 
  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  // Return the one's complement of sum
  return((uint16_t)(~sum));
}

/***************************************************
 * tcp checksum
 * calculate the TCP checksum when over IPv6
 **************************************************/
uint16_t 
tcp_checksum_ipv6(const void *buff, size_t len, size_t length, struct in6_addr *src_addr, struct in6_addr *dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  int i  ;
 
  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if (len)  // Add the padding if the packet length is odd
    sum += *((uint8_t *)buf);
 
  // Add the pseudo-header
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_TCP);
  sum += htons(length);
 
  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  // Return the one's complement of sum
  return((uint16_t)(~sum));
}


/***************************************************
 * udp checksum
 * calculate the UDP checksum when over IPv4
 **************************************************/
uint16_t 
udp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  int i  ;
 
  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if (len)  // Add the padding if the packet length is odd
    sum += *((uint8_t *)buf);
 
  // Add the pseudo-header
  for (i = 0 ; i <= 1 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 1 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_UDP);
  sum += htons(length);
 
  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  // Return the one's complement of sum
  return((uint16_t)(~sum));
}

/***************************************************
 * udp checksum
 * calculate the UDP checksum when over IPv6
 **************************************************/
uint16_t 
udp_checksum_ipv6(const void *buff, size_t len, size_t length, struct in6_addr *src_addr, struct in6_addr *dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  int i  ;
 
  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if (len)  // Add the padding if the packet length is odd
    sum += *((uint8_t *)buf);
 
  // Add the pseudo-header
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_UDP);
  sum += htons(length);
 
  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  // Return the one's complement of sum
  return((uint16_t)(~sum));
}


/***************************************************/

void ether_header(int IP_v, uint8_t *outpacket) {
  uint16_t ether_type;
  
  if (IP_v == 4) {
    ether_type = htons(0x0800);
    memcpy(outpacket, dst_mac_v4, 6);
  } else {
    ether_type = htons(0x86DD);
    memcpy(outpacket, dst_mac_v6, 6);
}
  memcpy(outpacket + 12, &ether_type, 2);
  memcpy(outpacket + 6, src_mac, 6);
}
/***************************************************/
/* Taken from the Linux kernel */
/** CRC table for the CRC-16. The poly is 0x8005 (x^16 + x^15 + x^2 + 1) */
uint16_t const crc16_table[256] = {
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static uint16_t crc16_byte(uint16_t crc, const uint8_t data) {
	return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

/**
 * crc16 - compute the CRC-16 for the data buffer
 * @crc:	previous CRC value
 * @buffer:	data pointer
 * @len:	number of bytes in the buffer
 *
 * Returns the updated CRC value.
 */
uint16_t crc16(uint16_t crc, uint8_t const *buffer, size_t len) {
	while (len--)
		crc = crc16_byte(crc, *buffer++);
	return crc;
}
/***************************************************/
int build_probe4(struct tr_conf *conf, int seq, u_int8_t ttl, uint8_t *outpacket, struct probe *probe) {
  struct iphdr *ip = (struct iphdr *)(outpacket + ETH_HDRLEN); // offset by ethernet header length
  u_char *p = ((u_char *)ip) + IP_HDR_LEN;
  struct udphdr *udphdr = (struct udphdr *)(p);
  struct tcphdr *tcphdr = (struct tcphdr *)(p);
  struct icmp *icmp_pkt = (struct icmp *)(p);
  struct packetdata *op;
  struct timespec ts;
  int proto_len;
  int tcp_opt_len;
  char *tcp_opts;

  uint16_t frame_len;

  ether_header(4, outpacket);

// Set the IPv4 header ID field to be the value of the TTL (to detect in transit manipulation)
  ip->id = htons(ttl);

  switch (probe->protocol) {
  case IPPROTO_ICMP:
    ip->protocol = IPPROTO_ICMP;
    frame_len = ETH_HDRLEN + IP_HDR_LEN + ICMP_HDRLEN + sizeof(struct packetdata);
    icmp_pkt->icmp_type = icmp_type;
    icmp_pkt->icmp_code = ICMP_CODE;
    icmp_pkt->icmp_seq = seq;
    icmp_pkt->icmp_id = conf->ident;
    op = (struct packetdata *)(icmp_pkt + 1);
    break;
  case IPPROTO_UDP:
    ip->protocol = IPPROTO_UDP;
    frame_len = ETH_HDRLEN + IP_HDR_LEN + UDP_HDR_LEN + sizeof(struct packetdata);
    // udphdr->uh_sport = conf->ident;
    udphdr->uh_sport = 443;
    udphdr->uh_dport = conf->port+seq; // Increment port with each step
    udphdr->uh_ulen = htons(frame_len - ETH_HDRLEN - sizeof(struct ip));
    udphdr->uh_sum = 0;
    op = (struct packetdata *)(udphdr + 1);
    break;
  case IPPROTO_TCP:
    ip->protocol = IPPROTO_TCP;
    tcphdr->source = crc16(0, (uint8_t const *)&(ip->daddr), 4)+ttl; // Source port is a checksum of the destination IP, add ttl to vary value
    tcphdr->dest = htons(conf->port);
    // Get seconds from top of the hour, including milliseconds
    struct timespec tp;
    int ret = clock_gettime(CLOCK_REALTIME, &tp);
    long sec_from_hour;
    uint32_t timestamp;
    if (ret == 0) {
      // if (debug) {
      //   printf("seconds: %ld\n", tp.tv_sec);
      //   printf("nanoseconds: %ld\n", tp.tv_nsec);
      // }
      sec_from_hour = tp.tv_sec %3600;
      // timestamp is an integer with the rightmost 3 digits being the milliseconds (*1000)
      timestamp = sec_from_hour*1000 + tp.tv_nsec/1000000;
      if (debug) {
        printf("timestamp: %ld %ld %d\n", sec_from_hour*1000, tp.tv_nsec/1000000, timestamp);
      }
    }
    tcphdr->seq = htonl(timestamp);
    tcphdr->ack_seq = 0;
    // tcphdr->doff=5;
    tcphdr->fin=0;
    tcphdr->syn=1;
    tcphdr->rst=0;
    tcphdr->psh=0;
    tcphdr->ack=0;
    tcphdr->urg=0;
    tcphdr->window = 5;
    tcphdr->check = 0;
    tcphdr->urg_ptr = 0;

    tcp_opts = (char *) (tcphdr + 1); ;
    tcp_opts[0] = 0x02 ;  // kind = 2 = mss
    tcp_opts[1] = 0x04 ;  // length = 4
    tcp_opts[2] = 0x05 ;  // mss val = 0x05a0 = 1440
    tcp_opts[3] = 0xa0 ;
    tcp_opts[4] = 0x04 ;  // kind = 4 = SACK permitted
    tcp_opts[5] = 0x02 ;  // length = 2
    tcp_opts[6] = 0x01 ;  // kind = 1 = fill
    tcp_opts[7] = 0x00 ;  // End of list

    tcp_opt_len = 8; // bytes
    tcphdr->doff= 5 + tcp_opt_len/4;

    proto_len = TCP_HDR_LEN + tcp_opt_len;
    // frame_len = ETH_HDRLEN + IP_HDR_LEN + TCP_HDR_LEN + sizeof(struct packetdata);
    frame_len = ETH_HDRLEN + IP_HDR_LEN + proto_len;
    // op = (struct packetdata *)(&(tcp_opts[12]));
    break;    
  default:
    op = (struct packetdata *)(ip + 1);
    break;
  }  
  ip->version = 4;
  ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(frame_len - ETH_HDRLEN);
  ip->id = ttl; // store the original TTL here
	ip->frag_off = 0;
  ip->ttl = ttl;
	ip->check = 0;
  // struct sockaddr_in *intermediate;
  // intermediate = (struct sockaddr_in *)(&(probe->src_addr));
  // ip->saddr = ((struct sockaddr_in *)&(probe->src_addr))->sin_addr.s_addr;
  // ip->daddr = ((struct sockaddr_in *)&(probe->dst_addr))->sin_addr.s_addr;

  memcpy(&(ip->saddr), &(probe->src_addr), 4);
  memcpy(&(ip->daddr), &(probe->dst_addr), 4);

	ip->check = htons(checksum((uint16_t *)ip, sizeof(struct iphdr)));
	
  // op->seq = seq;
  // op->ttl = ttl;
	// if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
	// 	err(1, "clock_gettime(CLOCK_MONOTONIC)");
  // }

  // op->sec = htonl(ts.tv_sec);
  // op->usec = htonl((ts.tv_nsec) % 1000000000);

  if (probe->protocol == IPPROTO_ICMP && icmp_type == ICMP_ECHO) {
    icmp_pkt->icmp_cksum = 0;
    icmp_pkt->icmp_cksum = checksum((u_short *)icmp_pkt, frame_len - sizeof(struct ip));
    if (icmp_pkt->icmp_cksum == 0) {
      icmp_pkt->icmp_cksum = 0xffff;
    }
  }
	if (probe->protocol == IPPROTO_UDP) {
		udphdr->uh_sum = udp_checksum_ipv4((uint16_t *)udphdr, UDP_HDR_LEN + sizeof(struct packetdata), UDP_HDR_LEN + sizeof(struct packetdata), (uint32_t *)&ip->saddr, (uint32_t *)&ip->daddr);
	}
  if (probe->protocol == IPPROTO_TCP) {
    // tcphdr->check =  tcp_checksum_ipv4(tcphdr, TCP_HDR_LEN + sizeof(struct packetdata), TCP_HDR_LEN + sizeof(struct packetdata), &ip->saddr, &ip->daddr);
    tcphdr->check =  tcp_checksum_ipv4(tcphdr, TCP_HDR_LEN + tcp_opt_len, TCP_HDR_LEN + tcp_opt_len, &ip->saddr, &ip->daddr);
  }
  return frame_len;
}

/***************************************************/
int build_probe6(struct tr_conf *conf, int seq, u_int8_t hops, uint8_t *outpacket, struct probe *probe) {
  struct timespec ts;
  struct packetdata *op;
  int i,status;
  int datalen = 0;
  uint16_t frame_len;
  int padding;
  int eh_len = 0;
  int proto_len;
  struct ip6_dest *hbh_hdr;
  uint8_t *hbh_opt;
  int eh;
  int tcp_opt_len;
  char *tcp_opts;


  ether_header(6, outpacket);
  
  struct ip6_hdr *ip6 = (struct ip6_hdr *)(outpacket + ETH_HDRLEN);
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  ip6->ip6_flow = htonl((6 << 28) | (0 << 20) | (uint8_t)hops);
  // Hop limit (8 bits): default to maximum value
  ip6->ip6_hops = hops;

  memcpy(&(ip6->ip6_src), &(probe->src_addr), 16);
  memcpy(&(ip6->ip6_dst), &(probe->dst_addr), 16);

  u_char *p = ((u_char *)ip6) + IP6_HDR_LEN;
  eh = probe->v6_options.type;
  if (eh != NEXTHDR_NONE) { // Add extension header, if requested
    switch (eh) {
      case NEXTHDR_HOP:
        ip6->ip6_nxt = NEXTHDR_HOP ; // hop by hop ext header
        if (debug) printf("EH: HBH\n");
        break;
      case NEXTHDR_DEST:
        ip6->ip6_nxt = NEXTHDR_DEST ; // destination ext header
        if (debug) printf("EH: DST\n");
        break;
      default:
        ip6->ip6_nxt = IPPROTO_TCP;
        if (debug) printf("Default: Unknown or undefined EH\n");
    }
    eh_len = 4;
    // now set up the HBH or dest header
    hbh_hdr = (struct ip6_dest *) p;
    // select padding size
    hbh_hdr->ip6d_len = (probe->v6_options.size / 8) - 1;  // Set option header length (does not include the first 8 bytes), in 8-byte units
    hbh_opt = (uint8_t *)hbh_hdr + 2;
    *hbh_opt = 0x01; // Option is one of the ones reserved for experiments
    padding = probe->v6_options.size - 4;  // PADN data option length, in bytes
    *(hbh_opt + 1) = padding; 

    // write 0 into padding payload
    int pad_count;
    for (pad_count = 0; pad_count < padding; pad_count++) {
      * (hbh_opt + 2 + pad_count) = 0;
      eh_len ++;
    }
    switch (probe->protocol) {
      case IPPROTO_ICMP:
        // Next header (8 bits): 58 for ICMP
        hbh_hdr->ip6d_nxt = IPPROTO_ICMPV6;
        break;
      case IPPROTO_UDP:
        // Next header (8 bits)
        hbh_hdr->ip6d_nxt = IPPROTO_UDP;
        break;
      case IPPROTO_TCP:
        hbh_hdr->ip6d_nxt = IPPROTO_TCP;
    }
    p = p + eh_len;
  } else {
    if (debug) printf("No extension headers\n");
    ip6->ip6_nxt = probe->protocol ; // UDP/TCP/ICMP header
  }

  struct udphdr *udphdr = (struct udphdr *) p;
  struct tcphdr *tcphdr = (struct tcphdr *) p;
  struct icmp6_hdr *icp = (struct icmp6_hdr *) p;  

  switch (probe->protocol) {
    case IPPROTO_ICMP:
      frame_len = ETH_HDRLEN + IP6_HDR_LEN + eh_len +   ICMP6_HDRLEN + sizeof(struct packetdata);
      // struct icmp6_hdr *icp = (struct icmp6_hdr *)(outpacket+ETH_HDRLEN+IP6_HDR_LEN);
      icp->icmp6_type = htons(ICMP6_ECHO_REQUEST);
      icp->icmp6_code = 0;
      icp->icmp6_id = htons(conf->ident);
      icp->icmp6_seq = htons(seq);
      icp->icmp6_cksum = 0;
      icp->icmp6_cksum = icmp6_checksum(ip6, icp, NULL, datalen);
      op = (struct packetdata *)(outpacket + ETH_HDRLEN + IP6_HDR_LEN + ICMP6_HDRLEN);
      proto_len = 8;
      break;
    case IPPROTO_UDP:
      frame_len = ETH_HDRLEN + IP6_HDR_LEN + eh_len + UDP_HDR_LEN + sizeof(struct packetdata);
      udphdr->uh_sport = htons(conf->ident);
      udphdr->uh_dport = htons(conf->port+seq);
      udphdr->uh_ulen = htons(frame_len - ETH_HDRLEN - sizeof(struct ip6_hdr));
      udphdr->uh_sum = 0;
      op = (struct packetdata *)(udphdr + 1);
      proto_len = 8;
      break;
    case IPPROTO_TCP:
      // frame_len = ETH_HDRLEN + IP6_HDR_LEN + eh_len + TCP_HDR_LEN + sizeof(struct packetdata);
      tcphdr->source = crc16(0, (uint8_t const *)&(ip6->ip6_dst), 16); // Source port is a checksum of the destination IP
      tcphdr->dest = htons(conf->port);
      tcphdr->check = 0;
      // Get seconds from top of the hour, including milliseconds
      struct timespec tp;
      int ret = clock_gettime(CLOCK_REALTIME, &tp);
      long sec_from_hour;
      uint32_t timestamp;
      if (ret == 0) {
        // if (debug) {
        //   printf("seconds: %ld\n", tp.tv_sec);
        //   printf("nanoseconds: %ld\n", tp.tv_nsec);
        // }
        sec_from_hour = tp.tv_sec % 3600;
        // timestamp is an integer with the rightmost 3 digits being the milliseconds (*1000)
        timestamp = sec_from_hour*1000 + tp.tv_nsec/1000000;
        if (debug) {
          printf("timestamp: %ld %ld %d\n", sec_from_hour*1000, tp.tv_nsec/1000000, timestamp);
        }
      }
      tcphdr->seq = htonl(timestamp);
      tcphdr->ack_seq = 0;
      tcphdr->doff=5;
      tcphdr->fin=0;
      tcphdr->syn=1;
      tcphdr->rst=0;
      tcphdr->psh=0;
      tcphdr->ack=0;
      tcphdr->urg=0;
      tcphdr->window = 5;
      tcphdr->check = 0;
      tcphdr->urg_ptr = 0;
      tcp_opts = (char *) (tcphdr + 1); ;
      tcp_opts[0] = 0x02 ;  // kind = 2 = mss
      tcp_opts[1] = 0x04 ;  // length = 4
      tcp_opts[2] = 0x05 ;  // mss val = 0x05a0 = 1440
      tcp_opts[3] = 0xa0 ;
      tcp_opts[4] = 0x04 ;  // kind = 4 = SACK permitted
      tcp_opts[5] = 0x02 ;  // length = 2
      tcp_opts[6] = 0x01 ;  // kind = 1 = fill
      tcp_opts[7] = 0x00 ;  // End of list

      tcp_opt_len = 8;
      tcphdr->doff= 5 + tcp_opt_len/4;

      proto_len = TCP_HDR_LEN + tcp_opt_len;
      frame_len = ETH_HDRLEN + IP6_HDR_LEN + eh_len + proto_len;
      // op = (struct packetdata *)(&(tcp_opts[12]));
      break;    
    default:
      op = (struct packetdata *)(ip6 + 1);
  }


  // op->sec = htonl(ts.tv_sec);
  // op->usec = htonl((ts.tv_nsec) % 1000000000);
  // op->seq = seq;
  // op->ttl = hops;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
    err(1, "clock_gettime(CLOCK_MONOTONIC)");
	}

  // Payload length (16 bits)
  ip6->ip6_plen = htons(eh_len + proto_len + datalen);

  // TODO
  // if (probe->protocol == IPPROTO_ICMP && icmp_type == ICMP_ECHO) {
  //   icmp_pkt->icmp_cksum = 0;
  //   icmp_pkt->icmp_cksum = checksum((u_short *)icmp_pkt, frame_len - sizeof(struct ip6_hdr));
  //   if (icmp_pkt->icmp_cksum == 0) {
  //     icmp_pkt->icmp_cksum = 0xffff;
  //   }
  // }
	if (probe->protocol == IPPROTO_UDP) {
		udphdr->uh_sum = udp_checksum_ipv6((uint16_t *)udphdr, UDP_HDR_LEN + sizeof(struct packetdata), UDP_HDR_LEN + sizeof(struct packetdata), &ip6->ip6_src, &ip6->ip6_dst);
	}
  if (probe->protocol == IPPROTO_TCP) {
    tcphdr->check =  tcp_checksum_ipv6(tcphdr, TCP_HDR_LEN + tcp_opt_len, TCP_HDR_LEN + tcp_opt_len, &ip6->ip6_src, &ip6->ip6_dst);
    // tcphdr->check =  tcp_checksum_ipv6(tcphdr, TCP_HDR_LEN + sizeof(struct packetdata), TCP_HDR_LEN + sizeof(struct packetdata), &ip6->ip6_src, &ip6->ip6_dst);
  }
  return frame_len;
}

/***************************************************/
void send_probe(struct tr_conf *conf, int sndsock, int seq, u_int8_t ttl, struct probe *probe, FILE *log_f) {
  int len, addr_len;
  uint8_t outpacket[1514];
  icmp_type = ICMP_ECHO; /* default ICMP code/type */
  uint16_t frame_len;
  struct ip6_hdr *ip6;
  const u_char * p;
  int nxt_header;

  switch (probe->addr_family) {
  case 4:
    if (debug) printf("IPv4\n");
    frame_len = build_probe4(conf, seq, ttl, outpacket, probe);
    addr_len = sizeof(struct sockaddr_in);
    break;
  case 6:
    if (debug) printf("IPv6\n");
    frame_len = build_probe6(conf, seq, ttl, outpacket, probe);
    addr_len = sizeof(struct sockaddr_in6);
    break;
  default:
    errx(1, "unsupported AF: %d", (probe->addr_family));
    break;
  }

  if (debug) {
    printf("Packet dump:\n");
    print_ethernet_header((const u_char *)outpacket);
    if (probe->addr_family == 6) {
      print_ipv6_header((const u_char *)outpacket+ETH_HDRLEN);
      ip6 = (struct ip6_hdr *)(outpacket + ETH_HDRLEN);
      nxt_header = ip6->ip6_nxt;
      p = (const u_char *)ip6 + IP6_HDR_LEN;
      do {
        switch (nxt_header) {
          case IPPROTO_TCP:
            print_tcp_header(p);
            nxt_header = 0;
            break;
          case IPPROTO_UDP:
            print_udp_header(p);
            nxt_header = 0;
            break;
          case IPPROTO_ICMPV6:
            print_icmp6_header(p);
            nxt_header = 0;
            break;
          case 0: // Hop-by-hop EH
          case 60: // Destination EH
            printf("################\n");
            printf("Extension header\n");
            printf("################\n");
            nxt_header = (uint8_t) *p;
            p += ((uint8_t) *(p+1) + 1)* 8;
            break;
        }
      } while (nxt_header);
    } else {
      print_ipv4_header((const u_char *)outpacket+ETH_HDRLEN);
      if (probe->protocol == IPPROTO_ICMP) {
        print_icmp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
      } else if (probe->protocol == IPPROTO_UDP) {
        print_udp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
      } else if (probe->protocol == IPPROTO_TCP) {
        print_tcp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
      }
    }
  }
	
  struct ifreq ifreq_i;
  int if_name_len;
  if_name_len = strlen(conf->if_name);

  memset(&ifreq_i,0,sizeof(ifreq_i));
  if (if_name_len<sizeof(ifreq_i.ifr_name)) {
    strncpy(ifreq_i.ifr_name, conf->if_name, if_name_len); //giving name of Interface
  } else {
      perror("interface name is too long");
  }

	if((ioctl(sndsock,SIOCGIFINDEX,&ifreq_i))<0) {
    perror("error in index ioctl reading");//getting Index Name
	}
 
  char ifname[256];
	if (debug) printf("interface index=%d, interface: %s\n",ifreq_i.ifr_ifindex, if_indextoname(ifreq_i.ifr_ifindex, ifname));
  
	struct sockaddr_ll sadr_ll;
	memset(&sadr_ll, 0, sizeof(sadr_ll));
	sadr_ll.sll_family = AF_PACKET;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address

  if (probe->addr_family == 4) {
  	memcpy(sadr_ll.sll_addr, dst_mac_v4, ETH_ALEN);
  } else if (probe->addr_family == 6) {
    memcpy(sadr_ll.sll_addr, dst_mac_v6, ETH_ALEN);
  }
  
  len = sendto(sndsock, outpacket, frame_len, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll));
	if (debug) printf("sent %d bytes on socket %d\n", len, sndsock);
  if (len == -1 || len != frame_len)  {
    if (len == -1) {
	    warn("sendto");    	
    }
    if (debug) fprintf(log_f, "sendto wrote %d chars, ret=%d\n", len, len);
    (void) fflush(stdout);
  }
}

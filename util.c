#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
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

void ether_header(int IP_v, uint8_t *outpacket) {
  uint16_t ether_type;

  // uint8_t src_mac[] = {0x6a, 0x89, 0x86, 0xa8, 0xdb, 0xf7}; // for the mac mini UTM VM
  // uint8_t dst_mac[] = {0x16, 0x98, 0x77, 0x25, 0xf5, 0x64}; //
  // uint8_t dst_mac[] = {0xd8, 0x58, 0xd7, 0x00, 0x37, 0x1d}; // at home
  uint8_t src_mac[] = {0xf2, 0x3c, 0x91, 0xd5, 0x03, 0x95}; // for testbed-de
  uint8_t dst_mac[] = {0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x04}; // for testbed-de's gateway

  
  memcpy(outpacket,     dst_mac, 6);
  memcpy(outpacket + 6, src_mac, 6);
  if (IP_v == 4) {
    ether_type = htons(0x0800);
  } else {
    ether_type = htons(0x86DD);
  }
  memcpy(outpacket + 12, &ether_type, 2);
}

void build_probe4(struct tr_conf *conf, int seq, u_int8_t ttl, uint8_t *outpacket, struct sockaddr_in *to, struct sockaddr_in *from) {
  struct iphdr *ip = (struct iphdr *)(outpacket + ETH_HDRLEN); // offset by ethernet header length
  u_char *p = ((u_char *)ip) + IP_HDR_LEN;
  struct udphdr *udphdr = (struct udphdr *)(p);
  struct tcphdr *tcphdr = (struct tcphdr *)(p);
  struct icmp *icmp_pkt = (struct icmp *)(p);
  struct packetdata *op;
  struct timespec ts;

  uint16_t frame_len;

  ether_header(4, outpacket);

  switch (conf->proto) {
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
    udphdr->uh_sport = conf->ident;
    udphdr->uh_dport = conf->port+seq; // Increment port with each step
    udphdr->uh_ulen = htons(frame_len - ETH_HDRLEN - sizeof(struct ip));
    udphdr->uh_sum = 0;
    op = (struct packetdata *)(udphdr + 1);
    break;
  case IPPROTO_TCP:
    ip->protocol = IPPROTO_TCP;
    frame_len = ETH_HDRLEN + IP_HDR_LEN + TCP_HDR_LEN + sizeof(struct packetdata);
    tcphdr->source = htons(conf->ident);
    tcphdr->dest = htons(conf->port+seq); // Increment port with each step
    tcphdr->seq = htonl(1234567);
    tcphdr->ack_seq = 0;
    tcphdr->doff=5;
    tcphdr->fin=0;
    tcphdr->syn=0;
    tcphdr->rst=0;
    tcphdr->psh=0;
    tcphdr->ack=0;
    tcphdr->urg=0;
    tcphdr->window = 5;
    tcphdr->check = 0;
    tcphdr->urg_ptr = 0;
    op = (struct packetdata *)(tcphdr + 1);
    break;    
  default:
    op = (struct packetdata *)(ip + 1);
    break;
  }
  
  ip->version = 4;
  ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(frame_len - ETH_HDRLEN);
  ip->id = htons(conf->ident+seq);
	ip->frag_off = 0;
  ip->ttl = ttl;
	ip->check = 0;
  ip->saddr = from->sin_addr.s_addr;
  ip->daddr = to->sin_addr.s_addr;
  
	ip->check = htons(checksum((uint16_t *)ip, sizeof(struct iphdr)));
	
  op->seq = seq;
  op->ttl = ttl;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		err(1, "clock_gettime(CLOCK_MONOTONIC)");

  op->sec = htonl(ts.tv_sec);
  op->usec = htonl((ts.tv_nsec) % 1000000000);

  if (conf->proto == IPPROTO_ICMP && icmp_type == ICMP_ECHO) {
    icmp_pkt->icmp_cksum = 0;
    icmp_pkt->icmp_cksum = checksum((u_short *)icmp_pkt, frame_len - sizeof(struct ip));
    if (icmp_pkt->icmp_cksum == 0) {
      icmp_pkt->icmp_cksum = 0xffff;
    }
  }
	if (conf->proto == IPPROTO_UDP) {
		udphdr->uh_sum = udp_checksum_ipv4((uint16_t *)udphdr, UDP_HDR_LEN + sizeof(struct packetdata), UDP_HDR_LEN + sizeof(struct packetdata), (uint32_t *)&ip->saddr, (uint32_t *)&ip->daddr);
	}
  if (conf->proto == IPPROTO_TCP) {
    tcphdr->check =  tcp_checksum_ipv4(tcphdr, TCP_HDR_LEN + sizeof(struct packetdata), TCP_HDR_LEN + sizeof(struct packetdata), &ip->saddr, &ip->daddr);
  }
}

void build_probe6(struct tr_conf *conf, int seq, u_int8_t hops, uint8_t *outpacket, struct sockaddr_in6 *to, struct sockaddr_in6 *from, int sndsock) {

  struct timespec ts;
  struct packetdata *op;
  int i,status;
  int datalen = 0;
  uint16_t frame_len;

  ether_header(6, outpacket);
  
  struct ip6_hdr *ip6 = (struct ip6_hdr *)(outpacket + ETH_HDRLEN);
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  ip6->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
  // Payload length (16 bits): ICMP header + ICMP data
  ip6->ip6_plen = htons(ICMP6_HDRLEN + datalen);
  // Hop limit (8 bits): default to maximum value
  ip6->ip6_hops = hops;

 // // Source IPv6 address (128 bits)
 //  if ((status = inet_pton(AF_INET6, src_ip, &(ip6->ip6_src))) != 1) {
 //    fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
 //    exit (1);
 //  }
 //
 //  // Destination IPv6 address (128 bits)
 //  if ((status = inet_pton (AF_INET6, dst_ip, &(ip6->ip6_dst))) != 1) {
 //    fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
 //    exit (1);
 //  }

  ip6->ip6_src = from->sin6_addr;
  ip6->ip6_dst = to->sin6_addr;

  i = hops;
  if (setsockopt(sndsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&i, sizeof(i)) == -1) {
    warn("setsockopt IPV6_UNICAST_HOPS");
  }

  u_char *p = ((u_char *)ip6) + IP6_HDR_LEN;
  struct udphdr *udphdr = (struct udphdr *)(p);
  struct icmp6_hdr *icp = (struct icmp6_hdr *)(p);

  switch (conf->proto) {
    case IPPROTO_ICMP:
      // Next header (8 bits): 58 for ICMP
      ip6->ip6_nxt = IPPROTO_ICMPV6;
      frame_len = ETH_HDRLEN + IP6_HDR_LEN + ICMP6_HDRLEN + sizeof(struct packetdata);
      // struct icmp6_hdr *icp = (struct icmp6_hdr *)(outpacket+ETH_HDRLEN+IP6_HDR_LEN);
      icp->icmp6_type = htons(ICMP6_ECHO_REQUEST);
      icp->icmp6_code = 0;
      icp->icmp6_id = htons(conf->ident);
      icp->icmp6_seq = htons(seq);
      icp->icmp6_cksum = 0;
      icp->icmp6_cksum = icmp6_checksum(ip6, icp, NULL, datalen);
      op = (struct packetdata *)(outpacket + ETH_HDRLEN + IP6_HDR_LEN + ICMP6_HDRLEN);
      break;
    case IPPROTO_UDP:
      // Next header (8 bits)
      ip6->ip6_nxt = IPPROTO_UDP;
      frame_len = ETH_HDRLEN + IP6_HDR_LEN + UDP_HDR_LEN + sizeof(struct packetdata);
      udphdr->uh_sport = htons(conf->ident);
      udphdr->uh_dport = htons(conf->port+seq);
      udphdr->uh_ulen = htons(frame_len - ETH_HDRLEN - sizeof(struct ip6_hdr));
      udphdr->uh_sum = 0;
      op = (struct packetdata *)(udphdr + 1);
      break;
    default:
    op = (struct packetdata *)(ip6 + 1);
  }
  op->sec = htonl(ts.tv_sec);
  op->usec = htonl((ts.tv_nsec) % 1000000000);
  op->seq = seq;
  op->ttl = hops;
  ((struct sockaddr_in6 *)to)->sin6_port = htons(conf->port + seq);
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
    err(1, "clock_gettime(CLOCK_MONOTONIC)");
	}
}

void send_probe(struct tr_conf *conf, int sndsock, int seq, u_int8_t ttl, struct sockaddr *to, struct sockaddr *from) {
  int len, addr_len;
  int v6flag;
  uint8_t outpacket[1514];
  icmp_type = ICMP_ECHO; /* default ICMP code/type */
  
  // int x;
  // struct ifreq ifreq;
  // memset(&ifreq,0,sizeof(ifreq));
  // strncpy(ifreq.ifr_name, "eth0", IFNAMSIZ-1); //giving name of Interface

  // printf("######PRE:\n");
  // for(x = 1; x < 3; x++){
  //         ifreq.ifr_ifindex = x;
  //         if(ioctl(sndsock, SIOCGIFNAME, &ifreq) < 0 )
  //                 perror("ioctl SIOCGIFNAME error");
  //         printf("index %d is %s\n", x, ifreq.ifr_name);
  // }


  switch (to->sa_family) {
  case AF_INET:
    printf("IPv4\n");
    v6flag = 0;
    build_probe4(conf, seq, ttl, outpacket, (struct sockaddr_in *)to, (struct sockaddr_in *)from);
    addr_len = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    printf("IPv6\n");
    v6flag = 1;
    build_probe6(conf, seq, ttl, outpacket, (struct sockaddr_in6 *)to, (struct sockaddr_in6 *)from, sndsock);
    addr_len = sizeof(struct sockaddr_in6);
    break;
  default:
    errx(1, "unsupported AF: %d", to->sa_family);
    break;
  }

  printf("Packet dump:\n");
  print_ethernet_header((const u_char *)outpacket);
  if (v6flag) {
    print_ipv6_header((const u_char *)outpacket+ETH_HDRLEN);
    if (conf->proto == IPPROTO_ICMP) {
      print_icmp6_header((const u_char *)outpacket+ETH_HDRLEN+IP6_HDR_LEN);
    } else if (conf->proto == IPPROTO_UDP) {
      print_udp_header((const u_char *)outpacket+ETH_HDRLEN+IP6_HDR_LEN);
    } else if (conf->proto == IPPROTO_TCP) {
      print_tcp_header((const u_char *)outpacket+ETH_HDRLEN+IP6_HDR_LEN);
    }
  } else {
    print_ipv4_header((const u_char *)outpacket+ETH_HDRLEN);
    if (conf->proto == IPPROTO_ICMP) {
      print_icmp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
    } else if (conf->proto == IPPROTO_UDP) {
      print_udp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
    } else if (conf->proto == IPPROTO_TCP) {
      print_tcp_header((const u_char *)outpacket+ETH_HDRLEN+IP_HDR_LEN);
    }

  }
	
  struct ifreq ifreq_i;
  char *if_name = "eth0";
  int if_name_len = strlen(if_name);

  memset(&ifreq_i,0,sizeof(ifreq_i));
  if (if_name_len<sizeof(ifreq_i.ifr_name)) {
    strncpy(ifreq_i.ifr_name, if_name, if_name_len); //giving name of Interface
  } else {
      perror("interface name is too long");
  }

	if((ioctl(sndsock,SIOCGIFINDEX,&ifreq_i))<0) {
    perror("error in index ioctl reading");//getting Index Name
	}
 
  char ifname[256];
	printf("interface index=%d, interface: %s\n",ifreq_i.ifr_ifindex, if_indextoname(ifreq_i.ifr_ifindex, ifname));
  
	struct sockaddr_ll sadr_ll;
	memset(&sadr_ll, 0, sizeof(sadr_ll));
	sadr_ll.sll_family = AF_PACKET;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
  uint8_t dst_mac[] = {0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x04}; // for testbed-de's gateway
  // uint8_t dst_mac[] = {0x16, 0x98, 0x77, 0x25, 0xf5, 0x64}; // mac mini @home
	memcpy(sadr_ll.sll_addr, dst_mac, ETH_ALEN);

  uint16_t frame_len;
  if (v6flag) {
  	frame_len = ETH_HDRLEN + IP6_HDR_LEN + ICMP6_HDRLEN + sizeof(struct packetdata);
  } else {
  	frame_len = ETH_HDRLEN + IP_HDR_LEN + UDP_HDR_LEN + sizeof(struct packetdata);
  }
  len = sendto(sndsock, outpacket, frame_len, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll));
	printf("sent %d bytes on socket %d\n", len, sndsock);
  if (len == -1 || len != frame_len)  {
    if (len == -1) {
	    warn("sendto");    	
    }
    printf("sendto wrote %d chars, ret=%d\n", len, len);
    (void) fflush(stdout);
  }
}

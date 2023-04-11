#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/times.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <sys/select.h>
#include <time.h>
#include <bits/socket.h>
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "dbg-util.h"

// Functions used to print protocol headers for debugging
void print_ethernet_header(const u_char *buffer)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
     
    printf("Ethernet Header:\n");
    printf(" Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf(" Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf(" Protocol            : %.4X \n",ntohs(eth->h_proto));
}

void print_icmp6_header(const u_char *buffer) {
  struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr *)buffer;

  char *icmp_type[156];
  char *icmp_code[156][8];
  
  icmp_type[1] = "ICMP_DEST_UNREACH";    // Destination Unreachable
  // icmp_type[4] = "ICMP_SOURCE_QUENCH";   // Source Quench
  icmp_type[2] = "ICMP_PKT_TOO_BIG";  // Packet too big
  icmp_type[3] = "ICMP_TIME_EXCEEDED";  // Time Exceeded
  icmp_type[4] = "ICMP_PARAMETERPROB";  // Parameter Problem

  icmp_type[128] = "ICMP_ECHO";            // Echo Request
  icmp_type[129] = "ICMP_ECHOREPLY";       // Echo Reply
  icmp_type[130] = "Multicast Listener Query";
  icmp_type[131] = "Multicast Listener Query";
  icmp_type[132] = "Multicast Listener Query";
  icmp_type[133] = "ICMP_RTR_SOLIC";            // Router solicitation
  icmp_type[134] = "ICMP_RTR_ADV";            // Router advertisement
  icmp_type[135] = "ICMP_NGBR_SOLIC";            // Neighbour solicitation
  icmp_type[136] = "ICMP_NGBR_ADV";            // Neighbour advertisement
  icmp_type[137] = "ICMP_REDIRECT";        // Redirect (change route)
  icmp_type[138] = "";          // TODO
  icmp_type[139] = "";          // TODO
  icmp_type[140] = "";          // TODO
  icmp_type[141] = "";          // TODO
  icmp_type[142] = "";          // TODO
  icmp_type[143] = "";          // TODO
  icmp_type[144] = "";          // TODO
  icmp_type[145] = "";          // TODO
  icmp_type[146] = "";          // TODO
  icmp_type[147] = "";          // TODO
  icmp_type[148] = "";          // TODO
  icmp_type[149] = "";          // TODO
  icmp_type[150] = "";          // TODO
  icmp_type[151] = "";          // TODO
  icmp_type[152] = "";          // TODO
  icmp_type[153] = "";          // TODO
  icmp_type[154] = "";          // TODO
  icmp_type[155] = "";          // TODO

  #define UNREACH 0
  #define REDIRECT 1
  #define TIME_EXCEEDED 2

  icmp_code[UNREACH][0]  = "Destination network unreachable";
  icmp_code[UNREACH][1]  = "Communication administratively prohibited";
  icmp_code[UNREACH][2]  = "Beyond scope of source address";
  icmp_code[UNREACH][3]  = "Address unreachable";
  icmp_code[UNREACH][4]  = "Destination port unreachable";
  icmp_code[UNREACH][5]  = "source address failed ingress/egress policy";
  icmp_code[UNREACH][6]  = "reject route to destination";  
  icmp_code[UNREACH][7]  = "Source route failed";

  icmp_code[REDIRECT][0] = "Redirect Net";           // ICMP_REDIR_NET    
  icmp_code[REDIRECT][1] = "Redirect Host";          // ICMP_REDIR_HOST   
  icmp_code[REDIRECT][2] = "Redirect Net for TOS";   // ICMP_REDIR_NETTOS 
  icmp_code[REDIRECT][3] = "Redirect Host for TOS";  // ICMP_REDIR_HOSTTOS

  icmp_code[TIME_EXCEEDED][0] = "Hop limit exceeded";
  icmp_code[TIME_EXCEEDED][1] = "Fragment Reass time exceeded";

  printf("ICMPv6 Header:\n");
  printf(" Type:       %s (%u)\n", icmp_type[icmp6hdr->icmp6_type], (uint8_t)icmp6hdr->icmp6_type);
  printf(" Code:       %s (%u) \n", icmp_code[icmp6hdr->icmp6_type][icmp6hdr->icmp6_code], (unsigned int)icmp6hdr->icmp6_code);
  printf(" Checksum:   %u \n",(unsigned int)icmp6hdr->icmp6_cksum);
  printf(" Id:         %u \n",(unsigned int)icmp6hdr->icmp6_id);
  printf(" Seq:        %u \n",(unsigned int)icmp6hdr->icmp6_seq);
  printf(" Data %08X: \n", (unsigned int)icmp6hdr->icmp6_dataun.icmp6_un_data32[0]);
  Hexdump((const void*) buffer+sizeof(icmp6hdr), 8);
  
}

void print_icmp_header(const u_char *buffer) {
  
  struct icmphdr *icmp_header = (struct icmphdr *)buffer;
  
  char *icmp_type[19];
  char *icmp_code[19][16];
  char *code_str;
  
  icmp_type[0] = "ICMP_ECHOREPLY";       // Echo Reply
  icmp_type[3] = "ICMP_DEST_UNREACH";    // Destination Unreachable
  icmp_type[4] = "ICMP_SOURCE_QUENCH";   // Source Quench
  icmp_type[5] = "ICMP_REDIRECT";        // Redirect (change route)
  icmp_type[8] = "ICMP_ECHO";            // Echo Request
  icmp_type[11] = "ICMP_TIME_EXCEEDED";  // Time Exceeded
  icmp_type[12] = "ICMP_PARAMETERPROB";  // Parameter Problem
  icmp_type[13] = "ICMP_TIMESTAMP";      // Timestamp Request
  icmp_type[14] = "ICMP_TIMESTAMPREPLY"; // Timestamp Reply
  icmp_type[15] = "ICMP_INFO_REQUEST";   // Information Request
  icmp_type[16] = "ICMP_INFO_REPLY";     // Information Reply
  icmp_type[17] = "ICMP_ADDRESS";        // Address Mask Request
  icmp_type[18] = "ICMP_ADDRESSREPLY";   // Address Mask Reply

  #define UNREACH 0
  #define REDIRECT 1
  #define TIME_EXCEEDED 2

  icmp_code[UNREACH][0]  = "Destination network unreachable";
  icmp_code[UNREACH][1]  = "Destination host unreachable";
  icmp_code[UNREACH][2]  = "Destination protocol unreachable";
  icmp_code[UNREACH][3]  = "Destination port unreachable";
  icmp_code[UNREACH][4]  = "Fragmentation required, and DF flag set";
  icmp_code[UNREACH][5]  = "Source route failed";
  icmp_code[UNREACH][6]  = "Destination network unknown";
  icmp_code[UNREACH][7]  = "Destination host unknown";
  icmp_code[UNREACH][8]  = "Source host isolated";
  icmp_code[UNREACH][9]  = "Network administratively prohibited";
  icmp_code[UNREACH][10] = "Host administratively prohibited";
  icmp_code[UNREACH][11] = "Network unreachable for ToS";
  icmp_code[UNREACH][12] = "Host unreachable for ToS";
  icmp_code[UNREACH][13] = "Communication administratively prohibited";
  icmp_code[UNREACH][14] = "Host Precedence Violation";
  icmp_code[UNREACH][15] = "Precedence cutoff in effect";

  icmp_code[REDIRECT][0] = "Redirect Net";           // ICMP_REDIR_NET    
  icmp_code[REDIRECT][1] = "Redirect Host";          // ICMP_REDIR_HOST   
  icmp_code[REDIRECT][2] = "Redirect Net for TOS";   // ICMP_REDIR_NETTOS 
  icmp_code[REDIRECT][3] = "Redirect Host for TOS";  // ICMP_REDIR_HOSTTOS

  icmp_code[TIME_EXCEEDED][0] = "TTL count exceeded";            // ICMP_EXC_TTL
  icmp_code[TIME_EXCEEDED][1] = "Fragment Reass time exceeded";  // ICMP_EXC_FRAGTIME

  if (icmp_header->type <= 2) {
    code_str = icmp_code[icmp_header->type][icmp_header->code];
  } else {
    code_str = "";
  }

  printf("ICMPv4 Header:\n");
  printf(" Type:       %s (%u)\n", icmp_type[icmp_header->type], (uint8_t)icmp_header->type);
  printf(" Code:       %s (%u) \n", code_str, (unsigned int)icmp_header->code);
  printf(" Checksum:   %u \n",(unsigned int)icmp_header->checksum);
}

void print_ipv4_header(const u_char *buffer)
{
    struct sockaddr_in src,dst;
    struct iphdr *ip_hdr = (struct iphdr *)(buffer);
     
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = ip_hdr->saddr;
     
    memset(&dst, 0, sizeof(dst));
    dst.sin_addr.s_addr = ip_hdr->daddr;

    printf("IPv4 Header:\n");
    printf(" IP Version        : %d\n", ip_hdr->version);
    printf(" IP Header Length  : %d Bytes\n", ip_hdr->ihl * 4);
    printf(" Type Of Service   : %d\n", (unsigned int)ip_hdr->tos);
    printf(" IP Total Length   : %d  Bytes\n", ntohs(ip_hdr->tot_len));
    printf(" Identification    : %d\n", ntohs(ip_hdr->id));
    // printf(" Reserved ZERO Field   : %d\n",(unsigned int)ip_hdr->ip_reserved_zero);
    // printf(" Dont Fragment Field   : %d\n",(unsigned int)ip_hdr->ip_dont_fragment);
    // printf(" More Fragment Field   : %d\n",(unsigned int)ip_hdr->ip_more_fragment);
    printf(" TTL      : %d\n",(unsigned int)ip_hdr->ttl);
    printf(" Protocol : %d\n",(unsigned int)ip_hdr->protocol);
    printf(" Checksum : %1$d / %1$#04x\n",ntohs(ip_hdr->check));
    printf(" Source IP        : %s\n" , inet_ntoa(src.sin_addr) );
    printf(" Destination IP   : %s\n" , inet_ntoa(dst.sin_addr) );
}

void print_ipv6_header(const u_char *buffer)
{
    struct in6_addr *src, *dst;
    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(buffer);
    char addr_str[INET6_ADDRSTRLEN];
     
    src = &(ipv6_hdr->ip6_src);
    dst = &(ipv6_hdr->ip6_dst);
    
    uint32_t ip6_un1_flow = ntohl(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_flow);
    int version = ip6_un1_flow >> 28;
    // int tc = (ip6_un1_flow & 0xFF00000) >> 20;
    int flow_label = ip6_un1_flow & 0xFFFFF;
    // int tc = ntohs((ip6_un1_flow & 0xFF00000) >> 20);
    // int flow_label = ntohs(ip6_un1_flow & 0xFFFFF);

    printf("IPv6 Header:\n");
    printf(" IP Version        : %d\n", version);
    // printf(" Traffic class   : %d\n", kkkkktc);
    printf(" IP Payload Length   : %d  Bytes\n",ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf(" Next header.     : %d\n", (uint8_t)ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf(" Hop Limit        : %d\n", (uint8_t)ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    printf(" Source IP        : %s\n" , inet_ntop(AF_INET6, src, addr_str, INET6_ADDRSTRLEN));
    printf(" Destination IP   : %s\n" , inet_ntop(AF_INET6, dst, addr_str, INET6_ADDRSTRLEN));
}

void print_tcp_header(const u_char * buffer)
{
    struct tcphdr *tcph=(struct tcphdr*)(buffer);

    printf("TCP Header:\n");
    printf(" Source Port      : %u\n",ntohs(tcph->source));
    printf(" Destination Port : %u\n",ntohs(tcph->dest));
    printf(" Sequence Number    : %u\n",ntohl(tcph->seq));
    printf(" Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf(" Header Length      : %d BYTES\n" ,(unsigned int)tcph->doff*4);
    // printf(" CWR Flag : %d\n",(unsigned int)tcph->cwr);
    // printf(" ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf(" Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf(" Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf(" Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf(" Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf(" Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf(" Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf(" Window         : %d\n",ntohs(tcph->window));
    printf(" Checksum       : %1$d / %1$#04x\n",ntohs(tcph->check));
    printf(" Urgent Pointer : %d\n",tcph->urg_ptr);
}

void print_tcp_header_with_pseudo_header(const u_char * buffer)
{
    struct tcphdr *tcph=(struct tcphdr*)(buffer + 12);

    printf(">>>>>>>>>>>>>>> PseudoHeader:\n");
    printf(" Source IP        : %s\n" , inet_ntoa(*((struct in_addr *)buffer )) );
    printf(" Destination IP   : %s\n" , inet_ntoa(*((struct in_addr *)(buffer + 4))) );
    printf(" Zero field : %d\n",(uint8_t)*(buffer + 8));
    printf(" Protocol : %d\n",(uint8_t)*(buffer + 9));
    // uint16_t * p_len = (uint16_t *)(buffer + 10);
    printf(" Length   : %d  Bytes\n",ntohs(*(uint16_t *)(buffer + 10)));
    // printf(" Length   : %d  Bytes\n",ntohs(*p_len));
    printf(">>>>>>>>>>>>>>> TCP Header:\n");
    printf(" Source Port      : %u\n",ntohs(tcph->source));
    printf(" Destination Port : %u\n",ntohs(tcph->dest));
    printf(" Sequence Number    : %u\n",ntohl(tcph->seq));
    printf(" Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf(" Header Length      : %d BYTES\n" ,(unsigned int)tcph->doff*4);
    // printf(" CWR Flag : %d\n",(unsigned int)tcph->cwr);
    // printf(" ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf(" Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf(" Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf(" Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf(" Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf(" Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf(" Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf(" Window         : %d\n",ntohs(tcph->window));
    printf(" Checksum       : %1$d / %1$#04x\n",ntohs(tcph->check));
    printf(" Urgent Pointer : %d\n",tcph->urg_ptr);
}

void print_udp_header(const u_char * buffer)
{
    struct udphdr *udphdr = (struct udphdr *) buffer;

    printf("UDP Header:\n");
    printf(" Source Port      : %u\n",udphdr->source);
    printf(" Destination Port : %u\n",udphdr->dest);
    printf(" UDP Length      : %d BYTES\n" ,ntohs((unsigned int)udphdr->len));
    printf(" Checksum       : %1$d / %1$#04x\n",udphdr->check);
}

void Hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
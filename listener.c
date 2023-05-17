#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <err.h>
#include <errno.h>

#include <libgen.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <pcap.h>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/socket.h>
// #include <sys/sysctl.h>2332323
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>

#include "dbg-util.h"
#include "util.h"
#include "listener.h"

#define SNAP_LEN 8192

#define ETH_HDRLEN 14

#define IP_HDR_LEN 20
#define IP6_HDR_LEN 40
#define ICMP_HDR_LEN 8

#define NEXTHDR_HOP 0
#define NEXTHDR_DEST 60

int debug = 0;
static char *interface = "eth0";
static char *host_v6 = "2a01:7e01::f03c:91ff:fed5:395";
static char *host_v4 = "172.104.147.241";
static int  is_daemon = 0;
static char *ofilename = 0;
static int version = 0 ;
static FILE *ofile;

/*****************************************/
// Handle SIGHUP for log rotation
void handle_sighup(int sig) {
    // close the file descriptor to close
    fclose(ofile);
    
    // open the new file descriptor
    if ( (ofile = fopen(ofilename, "a")) == NULL) {
      perror("can't open new output/log file");
    }
}

/*****************************************/
void listen_for_icmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct ip6_hdr *ipv6_hdr;
  struct ip6_hdr *emb_ipv6_hdr;
  struct iphdr *ipv4_hdr;
  struct icmphdr *icmp_hdr;
  struct iphdr *emb_ipv4_hdr;
  struct icmp6_hdr *icmp6_hdr;
  struct tcphdr *tcp_hdr;
  struct tcphdr *emb_tcp_hdr;
  int eh_len;
  int ipv4 = 0;
  int ipv6 = 0;
  char icmp_src_addr_str[INET6_ADDRSTRLEN];
  char target_addr_str[INET6_ADDRSTRLEN];
  struct timeval now;
  long sec_from_hour;
  uint32_t timestamp;
  struct timespec tp;

  size_t packet_len = (size_t)header->caplen;

  uint16_t ethertype = *(packet + 12) *256 + *(packet + 13);
  if (ethertype == 0x0800) {
    ipv4 = 1;
    ipv6 = 0;
  } else if (ethertype == 0x86DD) {
    ipv6 = 1;
    ipv4 = 0;
  }

  if (debug) {
    if (ipv4) {
      printf("\n======\nGot v4 packet, %ld bytes captured\n", packet_len);
    } else if (ipv6) {
      printf("\n======\nGot v6 packet, %ld bytes captured\n", packet_len);
    } else printf("Packet was not IPv4 nor IPv6. Eth type = %04X\n",ethertype);
  }

  if (ipv4) {
    ipv4_hdr = (struct iphdr *)(packet + 14); 
    icmp_hdr = (struct icmphdr *)((const u_char *)ipv4_hdr+IP_HDR_LEN);
    emb_ipv4_hdr = (struct iphdr *)((const u_char *)icmp_hdr+ICMP_HDR_LEN);
    emb_tcp_hdr = (struct tcphdr *)((const u_char *)emb_ipv4_hdr+IP_HDR_LEN);

    if (debug) {
      print_ipv4_header((const u_char *)ipv4_hdr);
      print_icmp_header((const u_char *)icmp_hdr);
      // print ip header in icmp return payload
      print_ipv4_header((const u_char*)emb_ipv4_hdr);
      // Hexdump((const u_char*)emb_ipv4_hdr,8);
      print_tcp_header((const u_char*)emb_tcp_hdr);
    }
    if (icmp_hdr->type == 11 || icmp_hdr->type == 1) { // Process time exceeded or dest unreachable
      struct in_addr target;
      memcpy(&target, &(emb_ipv4_hdr->daddr),4);
      fprintf(ofile, "%s,",inet_ntoa(target));
      // IPv4
      // TODO Check crc of original IP address
      
      // IP address originating ICMP
      struct in_addr src;
      memcpy(&src, &(ipv4_hdr->saddr),4);
      fprintf(ofile, "%s,",inet_ntoa(src));
      // Original TTL, encoded in IP ID field
      fprintf(ofile, "%d,", emb_ipv4_hdr->id);
      // Verify checksum for target IP address
      uint16_t target_checksum;
      target_checksum = crc16(0, (uint8_t const *)&(target), 4);
      if (target_checksum == emb_tcp_hdr->source) {
        fprintf(ofile, "T,");
      } else {
        fprintf(ofile, "F,");
      }
      // Print elapsed time
      timestamp = ntohl(emb_tcp_hdr->seq);

      // Get seconds from top of the hour, including milliseconds
      int ret = clock_gettime(CLOCK_REALTIME, &tp);
      if (ret == 0) {
        sec_from_hour = tp.tv_sec % 3600;
        if (sec_from_hour < timestamp/1000) { // we went across the top of the  hour
          sec_from_hour += 3600;
        }
        // timestamp is an integer with the rightmost 3 digits being the milliseconds (*1000)
        // printf("packet timestamp: %u, min from hour: %u, ms: %u\n", timestamp, sec_from_hour, tp.tv_nsec/1000000);
        uint32_t elapsed_time = (sec_from_hour*1000 + tp.tv_nsec/1000000) - timestamp;
        fprintf(ofile, "%f", elapsed_time/1000.0);
      }
      fprintf(ofile, "\n");
    }
  } else if (ipv6) {
    // IPv6
    uint32_t orig_ttl;
    ipv6_hdr = (struct ip6_hdr *)(packet + 14);
    icmp6_hdr = (struct icmp6_hdr *)((uint8_t *)ipv6_hdr + IP6_HDR_LEN);
    emb_ipv6_hdr = (struct ip6_hdr *)((uint8_t *)icmp6_hdr + 8);

    // Are there any extension headers?
    eh_len = 0;
    if (emb_ipv6_hdr->ip6_nxt == NEXTHDR_HOP || emb_ipv6_hdr->ip6_nxt == NEXTHDR_DEST) {
      struct ip6_dest *hbh_hdr = (struct ip6_dest *)(emb_ipv6_hdr + IP6_HDR_LEN);
      eh_len = (hbh_hdr->ip6d_len + 1) * 8;
    }
    emb_tcp_hdr = (struct tcphdr *) ((uint8_t *)emb_ipv6_hdr + IP6_HDR_LEN + eh_len);

    if (debug) {
      print_ipv6_header((const u_char *)ipv6_hdr);
      print_icmp6_header((const u_char *)icmp6_hdr); // generic icmp6 header
      print_ipv6_header((const u_char *)emb_ipv6_hdr); // embedded IPv6 header in returned packet
      if (eh_len != 0) printf("EH of length %d\n", eh_len); 
      print_tcp_header((const u_char *) emb_tcp_hdr); // embedded TCP header
    }

    if (icmp6_hdr->icmp6_type == ICMP6_TIME_EXCEEDED || icmp6_hdr->icmp6_type == ICMP6_DST_UNREACH) {
      struct in6_addr *target_addr;
      target_addr = &(emb_ipv6_hdr->ip6_dst);
      inet_ntop(AF_INET6, target_addr, target_addr_str, INET6_ADDRSTRLEN);
      fprintf(ofile, "%s,",target_addr_str);
      inet_ntop(AF_INET6, &(ipv6_hdr->ip6_src), icmp_src_addr_str, INET6_ADDRSTRLEN);
      fprintf(ofile, "%s,",icmp_src_addr_str);

      // Original TTL, encoded in IP flow label field
      orig_ttl = ntohl(emb_ipv6_hdr->ip6_flow) & 0xFF; // Flow label: rightmost 8 bits
      fprintf(ofile, "%d,", orig_ttl);

      // IPv6
      // TODO Check crc of original IP address
      
      // Verify checksum for target IP address
      uint16_t target_checksum;
      target_checksum = crc16(0, (uint8_t const *)target_addr, 16);
      if (target_checksum == emb_tcp_hdr->source) {
        fprintf(ofile, "T,");
      } else {
        fprintf(ofile, "F,");
      }

      timestamp = ntohl(emb_tcp_hdr->seq);
      // Get seconds from top of the hour, including milliseconds
      struct timespec tp;
      int ret = clock_gettime(CLOCK_REALTIME, &tp);
      long sec_from_hour;
      if (ret == 0) {
        sec_from_hour = tp.tv_sec % 3600;
        if (sec_from_hour < timestamp/1000) { // we went across the top of the  hour
          sec_from_hour += 3600;
        }
        // timestamp is an integer with the rightmost 3 digits being the milliseconds (*1000)
        // printf("packet timestamp: %u, min from hour: %u, ms: %u\n", timestamp, sec_from_hour, tp.tv_nsec/1000000);
        uint32_t elapsed_time = (sec_from_hour*1000 + tp.tv_nsec/1000000) - timestamp;
        fprintf(ofile, "%f", elapsed_time/1000.0);
      }
      fprintf(ofile, "\n");
    } else {
      if (debug) {
        print_icmp6_header((const u_char *)icmp_hdr);
      }
    }
  }
  fflush(ofile);
}

/*****************************************/
void  daemonise() {
  // Standard fork and exit parent, leave child running.
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    exit(-1);
  }
  if (pid > 0) { // Exit the parent, let the child run
    exit(EXIT_SUCCESS);
  }
}

/*****************************************/
int main (int argc, char * const argv[])
{
  int ch ;

  char filter_exp[1024];           // The filter expression
  char errbuff[PCAP_ERRBUF_SIZE];  // error buffer
  struct bpf_program fp;           // The compiled filter expression
  pcap_t *pcap_handle ;            // packet capture handle

  while (((ch = getopt(argc,argv, "di:k:l:o:x"))) != -1) {
    switch(ch) {
      case 'd':
        // Stay in foreground. Default is to become daemon
        is_daemon = 1;
        break;
      case 'i':
        // interface name of client side address
        interface = strdup(optarg) ;
        break;
      case 'k':
        // IPv4 address to listen for
        host_v4 = strdup(optarg) ;
        version += 4;
        break ;
      case 'l':
        // IPv6 address to listen for
        host_v6 = strdup(optarg) ;
        version += 6;
        break ;
      case 'o':
        // Output file (otherwise stdout)
        ofilename = strdup(optarg);
        break;
      case 'x': // Turn on debug logging
        debug = 1;
        break;
      default:
        fprintf(stderr, "listener [-d]\n") ;
        exit (EXIT_FAILURE);
    }
  }

  // Open output file if one was given
  if (ofilename != 0) {
    ofile = fopen(ofilename, "a");
    if (ofile == NULL) {
      perror("can't open output/log file");
      exit(1);
    }
  } else {
    ofile = stdout;
  }

    // register the signal handler for SIGHUP
  if (signal(SIGHUP, handle_sighup) == SIG_ERR) {
    // handle error registering signal handler
    perror("Error registering signal handler");
    exit(1);
  }

  /* the PCAP capture filter  - ICMP(v6) traffic only*/
  if (version == 10) {
    sprintf(filter_exp,"dst host %s or dst host %s and (icmp or icmp6)", host_v6, host_v4);
    }
  else if (version == 4) {
    sprintf(filter_exp,"(dst host %s and icmp)", host_v4);
    }
  else if (version == 6) {
    sprintf(filter_exp,"dst host %s and icmp6",host_v6);
    }

  if (debug) printf("PCAP Filter: %s\n",filter_exp);

  /* open capture device */  
  if ((pcap_handle = pcap_open_live(interface, SNAP_LEN, 1, 1, errbuff)) == NULL) {
    fprintf(stderr, "Couldn't open client device %s: %s\n", interface, errbuff);
    exit(EXIT_FAILURE) ;
  }

  /* compile the filter expression */
  if (pcap_compile(pcap_handle, &fp, filter_exp, 0, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE) ;
  }

  /* install the filter */
  if (pcap_setfilter(pcap_handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE) ;
  }
  
  // Print header for CSV putput
  printf("Orig Dest, Src addr ICMP, ICMP type, arrival timestamp, other data\n");

  if (is_daemon == 1) {
    daemonise();
  }


  pcap_loop(pcap_handle, -1, listen_for_icmp, NULL);
  return 0;
}
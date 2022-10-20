#include <libgen.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#if __APPLE__
#include <netinet/if_ether.h>
#elif __linux__
#include <linux/if_ether.h>
#endif
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
// #include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dbg-util.h"
#include "util.h"
#include "listener.h"

#ifdef __linux__
#  if defined IPV6_RECVPKTINFO
#    include <linux/version.h>
#    if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#      if defined IPV6_2292PKTINFO
#        undef IPV6_RECVPKTINFO
#        undef IPV6_PKTINFO
#        define IPV6_RECVPKTINFO IPV6_2292PKTINFO
#        define IPV6_PKTINFO IPV6_2292PKTINFO
#      endif
#    endif
#  endif
#endif

#ifdef __linux__
#  if defined IP_PKTINFO
#    define HAVE_IP_PKTINFO
#  endif
#endif

/*
 *      Linux uses IPV6_RECVPKTINFO for the setsockopt() call,
 *      and IPV6_PKTINFO for sendmsg() and recvmsg()
 *      Others use IPV6_PKTINFO for all calls.
 */
#ifdef IPV6_PKTINFO
#ifdef __linux__
#define SSO_IPV6_RECVPKTINFO IPV6_RECVPKTINFO
#else
#define SSO_IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
#endif

#ifdef __APPLE__
#define SOL_IP IP_PKTINFO
#endif

#define ETH_HDRLEN 14

#define IP_HDR_LEN 20
#define IP6_HDR_LEN 40

int debug = 0;

/*****************************************/
void listen_for_icmp(int rcvsock4, int rcvsock6) {
  int i;
  #define MAX_PKT_SIZE 1514
  uint8_t inpacket[MAX_PKT_SIZE];
  struct sockaddr_in responder;
  static struct epoll_event ev4;
  static struct epoll_event ev6;
  struct epoll_event events[2];
  int nfds;
  struct icmp6_hdr *icmp6hdr;
  struct tcphdr *tcph;
  ssize_t rd_len;
  struct msghdr msgh;
  struct cmsghdr *cmsg;

  int epfd = epoll_create(2);

  memset(&responder, 0, sizeof (responder));
  int addr_len=sizeof(responder);

  // ev4.data.fd = rcvsock4;
  // ev4.events = EPOLLIN;
  // epoll_ctl(epfd, EPOLL_CTL_ADD, ev4.data.fd, &ev4);

  ev6.data.fd = rcvsock6;
  ev6.events = EPOLLIN;
  epoll_ctl(epfd, EPOLL_CTL_ADD, ev6.data.fd, &ev6);

  while(1){
    nfds = epoll_wait(epfd, events, 1, -1);
    if (nfds == -1) {
      perror("epoll_wait");
    }

     // for(i=0;i<nfds;i++) {
    memset(inpacket,0,MAX_PKT_SIZE);
    rd_len = read(events[i].data.fd, inpacket, MAX_PKT_SIZE);
    if (debug) {
      fprintf(stderr, "!!!!!!!!!!Received packet!!!!!!!\n");
      printf("Packet dump:\n");      
      Hexdump((const void*) inpacket, rd_len);
    }
    if (events[i].data.fd == rcvsock4) {
      print_ipv4_header((const u_char *)inpacket);
      print_icmp_header((const u_char *)inpacket+IP_HDR_LEN);
    }
    if (events[i].data.fd == rcvsock6) {
      // print_ipv6_header((const u_char *)inpacket+ETH_HDRLEN);
      // print_icmp6_header((const u_char *)inpacket+ETH_HDRLEN+IP6_HDR_LEN);
      for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
                         cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
                     if (cmsg->cmsg_level == IPPROTO_IPV6
                             && cmsg->cmsg_type == IP_TTL) {
                         memcpy(&receive_ttl, CMSG_DATA(cmsg), sizeof(received_ttl));
                         break;
                     }
                 }
      icmp6hdr = (struct icmp6_hdr *)inpacket;
      if (icmp6hdr->icmp6_type == 3) { // Time exceeded
        struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(inpacket+8);
        struct in6_addr *src, *dst;
        char addr_str[INET6_ADDRSTRLEN];

        src = &(ipv6_hdr->ip6_src);
        dst = &(ipv6_hdr->ip6_dst);
        printf ("Time exceeded ICMP6:\n");
        printf(" Source IP        : %s\n" , inet_ntop(AF_INET6, src, addr_str, INET6_ADDRSTRLEN));
        printf(" Destination IP   : %s\n" , inet_ntop(AF_INET6, dst, addr_str, INET6_ADDRSTRLEN));
        printf("Next header: %d\n", ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt );
        if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
        
        if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
          tcph=(struct tcphdr*)(ipv6_hdr + IP6_HDR_LEN);
          printf(" Source Port      : %u\n",ntohs(tcph->source));
          printf(" Destination Port : %u\n",ntohs(tcph->dest));
        }
        
      } else if (debug) {
        print_icmp6_header((const u_char *)inpacket); // generic icmp6 header
      }
    }
     // }
  
    // if ( recvfrom(rcvsock, &inpacket, sizeof(inpacket), 0, (struct sockaddr*)&src_addr, &addr_len) <= 0) {
    //   printf("\nPacket receive failed!\n");
    //   exit(1);
    // }
  }
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
int main (int argc, char **argv)
{
  // const char    *dest;
  const char    *source;

  struct sockaddr   *from, *to;
  struct addrinfo    hints, *res, *src_ip;
  const char  *hostname = NULL;
  char ch;
  int error;
  char  hbuf[NI_MAXHOST];
  
  struct sockaddr_in   from4, to4;
  struct sockaddr_in6  from6, to6;
  
  int rcvsock4 = -1;
  int rcvsock6 = -1;
  int v4sock_errno = 0;
  int v6sock_errno = 0;
  
  int proto, flag;
  int enable = 1;
  
  while (((ch = getopt(argc,argv, "d"))) != -1) {
    switch(ch) {
      case 'd': // Turn on debug logging
        debug = 1;
        break;
      default:
        fprintf(stderr, "listener [-d]\n") ;
        exit (EXIT_FAILURE);
    }
  }

// // IPv4
//   if (addr.ss_family == AF_INET) {
// #ifdef HAVE_IP_PKTINFO
//     // If on Linux
//     proto = SOL_IP;
//     flag = IP_PKTINFO;
// #endif
// #ifdef IP_RECVDSTADDR
//     proto = IPPROTO_IP;
//     // Set IP_RECVDSTADDR option (*BSD)
//     flag = IP_RECVDSTADDR;
// #endif
//   } else if (addr.ss_family == AF_INET6) {
// // IPv6
// #ifdef IPV6_PKTINFO
//     proto = IPPROTO_IPV6;
//     flag = SSO_IPV6_RECVPKTINFO;
// #endif
//   }
//   return setsockopt(socket, proto, flag, &enable, sizeof(enable));

  // IPv6
  #ifdef IPV6_PKTINFO
      proto = IPPROTO_IPV6;
      flag = SSO_IPV6_RECVPKTINFO;
  #endif
  if ((rcvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
    v6sock_errno = errno;

  if (v6sock_errno != 0) {
    errx(5, rcvsock6 < 0 ? "socket(ICMPv6)" : "socket(SOCK_DGRAM)");
    }

  #ifdef HAVE_IP_PKTINFO
      // If on Linux
      proto = SOL_IP;
      flag = IP_PKTINFO;
  #endif
  #ifdef IP_RECVDSTADDR
      proto = IPPROTO_IP;
      // Set IP_RECVDSTADDR option (*BSD)
      flag = IP_RECVDSTADDR;
  #endif
  
  // IPv4
  // if ((rcvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
  //   v4sock_errno = errno;
  // }
  // if (v4sock_errno != 0) {
  //   errx(5,rcvsock4 < 0 ? "icmp socket" : "raw socket");
  //   }

  printf("Receive socket v4: %d, receive socket v6: %d\n", rcvsock4, rcvsock6);

  /* specify to tell receiving interface */
  // if (setsockopt(rcvsock6, IPPROTO_IPV6, SSO_IPV6_RECVPKTINFO, &enable, sizeof(enable)))
  if (setsockopt(rcvsock6, IPPROTO_IPV6, IPV6_PKTINFO, &enable, sizeof(enable)))
    err(1, "setsockopt(IPV6_RECVPKTINFO)");
  if (setsockopt(rcvsock6, IPPROTO_IPV6, IPV6_HDRINCL, &enable, sizeof(enable)))
    err(1, "setsockopt(IPV6_HDRINCL)");
  // /* specify to tell hoplimit field of received IPv6 header */
  // if (setsockopt(rcvsock6, proto, flag, &enable, sizeof(enable)))
  //   err(1, "setsockopt(IPV6_RECVHOPLIMIT)");

  daemonise();
  listen_for_icmp(rcvsock4, rcvsock6);

  return 0;
}
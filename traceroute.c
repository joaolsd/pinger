#include <libgen.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
// #include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "util.h"
#include "traceroute.h"

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

/*****************************************/
void usage(char *progname) {
  printf("Give me an address\n");
	exit(0);
}
/*****************************************/
int main (int argc, char const *argv[])
{
  const char    *dest;
  const char    *source;
  struct tr_conf    *conf;  /* configuration defaults */

  struct sockaddr   *from, *to;
  struct addrinfo    hints, *res, *src_ip;
  const char  *hostname = NULL;
  char ch;
  int error;
  char  hbuf[NI_MAXHOST];
  
  struct sockaddr_in   from4, to4;
  struct sockaddr_in6  from6, to6;
  
  // int rcvsock;  /* receive (icmp) socket file descriptor */
  int sndsock;  /* send (udp) socket file descriptor */
  
  // int rcvsock4, rcvsock6;
  int sndsock4, sndsock6;
  int v4sock_errno = 0;
  int v6sock_errno = 0;
  
  int v6flag = 0;
  int proto, flag;
  int enable = 1;
  
  conf = calloc(1, sizeof(struct tr_conf));
  conf->incflag = 1;
  conf->first_ttl = 1;
  conf->proto = IPPROTO_UDP;
  // conf->proto = IPPROTO_ICMP;
  conf->max_ttl = IPDEFTTL;
  conf->nprobes = 3;
  
	conf->port = 33434;
	conf->ident = 666;
	
  char *progname = basename((char *)argv[0]);
  
  while ((ch = getopt(argc, (char * const *)argv, "h6i")) != (char)-1)
    switch (ch) {
      case 'h':
        usage(progname);
        break;
      case '6':
        v6flag = 1;
        break;
      case 'i':
        conf->proto = IPPROTO_ICMP;
        break;
      default:
        ;
    }

  argc -= optind;
  argv += optind;

  if (argc < 1 || argc > 3)
    usage(progname);
  

  dest = *argv;
  source = "172.104.147.241"; // testbed-de
  // source = "192.168.64.2"; // mac mini vm
  if (v6flag) {
    source = "2a01:7e01::f03c:91ff:fed5:395"; // testbed-de
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = v6flag ? AF_INET6 : AF_INET;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_CANONNAME;
  if ((error = getaddrinfo(dest, NULL, &hints, &res)))
    errx(1, "%s", gai_strerror(error));
  if ((error = getaddrinfo(source , NULL, &hints, &src_ip)))
    errx(1, "%s", gai_strerror(error));

  switch (res->ai_family) {
  case AF_INET:
    to = (struct sockaddr *)&to4;
    from = (struct sockaddr *)&from4;
    break;
  case AF_INET6:
    to = (struct sockaddr *)&to6;
    from = (struct sockaddr *)&from6;
    break;
  default:
    errx(1, "unsupported AF: %d", res->ai_family);
    break;
  }

  memcpy(to, res->ai_addr, res->ai_addrlen);
  memcpy(from, src_ip->ai_addr, src_ip->ai_addrlen);
  
  if (!hostname) {
    hostname = res->ai_canonname ? strdup(res->ai_canonname) : dest;
    printf("Hostname: %s\n", hostname);
    if (!hostname)
      errx(1, "malloc");
  }

  if (res->ai_next) {
    if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
        sizeof(hbuf), NULL, 0, NI_NUMERICHOST) != 0)
      strncpy(hbuf, "?", sizeof(hbuf));
    warnx("Warning: %s has multiple "
        "addresses; using %s", hostname, hbuf);
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

  if (v6flag) {
    #ifdef IPV6_PKTINFO
        proto = IPPROTO_IPV6;
        flag = SSO_IPV6_RECVPKTINFO;
    #endif
    // if ((sndsock6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
    if ((sndsock6 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
      v6sock_errno = errno;
    }

    if (v6sock_errno != 0) {
      perror("");
      errx(5, "socket(SOCK_DGRAM)");
    }

    sndsock = sndsock6;
    if (sndsock4 >= 0) {
      close(sndsock4);
    }
  } else {
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
    
    if ((sndsock4 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
      v4sock_errno = errno;
      perror("Can't open send socket");
    }

    if (v4sock_errno != 0) {
      errx(5, "raw socket");
      }
      
      sndsock = sndsock4;
      if (sndsock6 >= 0)
      close(sndsock6);
  }

	printf("Send socket: %d\n", sndsock);
  // if (v6flag) {
  //   /* specify to tell receiving interface */
  //   if (setsockopt(rcvsock, proto, flag, &enable, sizeof(enable)))
  //     err(1, "setsockopt(IPV6_RECVPKTINFO)");
  //   /* specify to tell hoplimit field of received IP6 hdr */
  //   if (setsockopt(rcvsock, proto, flag, &enable, sizeof(enable)))
  //     err(1, "setsockopt(IPV6_RECVHOPLIMIT)");
  // }
  int seq = 0;
  int ttl = 1;
  char addr_str[256];
  if (v6flag) {
    printf("Sending probe to %s, %s\n", hostname, inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)to)->sin6_addr), addr_str, 256));
  } else {
    printf("Sending probe to %s, %s\n", hostname, inet_ntop(AF_INET, &(((struct sockaddr_in *)to)->sin_addr), addr_str, 256));    
  }
  send_probe(conf, sndsock, seq, ttl, to, from);
  // send_probe(conf, sndsock, seq, 64, to, from);

  // freeaddrinfo(res);

  return 0;
}
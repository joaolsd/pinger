#define _GNU_SOURCE // Need for EAI_ADDRFAMILY and EAI_NODATA

#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

// #include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

int main (int argc, char const *argv[])
{
  struct addrinfo  hints, *src_ip;
  int error;
	char     *source4;   // Source IPv4 address to use
	char     *source6;   // Source IPv6 address to use

  source4 = "172.104.147.241";
  source6 = "2a01:7e01::f03c:91ff:fed5:395";

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_NUMERICHOST;
  if ((error = getaddrinfo(source4 , NULL, &hints, &src_ip))) {
    printf("Line: %d: ",__LINE__);
    errx(1, "%s", gai_strerror(error));
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_NUMERICHOST;
  if ((error = getaddrinfo(source6 , NULL, &hints, &src_ip))) {
    printf("Line: %d: ",__LINE__);
    errx(1, "%s", gai_strerror(error));
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_NUMERICHOST;
  if ((error = getaddrinfo(source4 , NULL, &hints, &src_ip))) {
    printf("Line: %d: ",__LINE__);
    printf("error: ,%d", EAI_ADDRFAMILY);
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_NUMERICHOST;
  if ((error = getaddrinfo(source6 , NULL, &hints, &src_ip))) {
    printf("Line: %d: ",__LINE__);
    errx(1, "%s", gai_strerror(error));
  }
}

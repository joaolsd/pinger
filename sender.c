#include <sys/types.h>
#include <sys/stat.h>
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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
// #include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "util.h"
#include "sender.h"


#include <net/if.h>
#include <sys/ioctl.h>

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

int is_daemon = 0;
int ret = 0;

/*****************************************/
void usage(char *progname) {
  printf("pinger [-f <filename>] [-d] [-h] [-6] [-t] [-i] [\"IPv4/v6 Address literal]\"");
  printf("-f: path to an input file or unix socket\n");
  printf("-d: daemonise (must use a socket to send input)\n");
  printf("-i: use ICMP\n");
  printf("-t: use TCP\n");
  printf("-h: this help");
	exit(0);
}
/*****************************************/
void socket_non_block (int socket) {
  // Make socket non-blocking
  int flags, s;
  flags = fcntl(socket, F_GETFL, 0);
  if (flags == -1) {
    perror ("fcntl error");
    exit(-1);
  }
  flags |= O_NONBLOCK; // Add non-blocking flag
  s = fcntl (socket, F_SETFL, flags);
  if (s == -1) {
    perror ("fcntl error");
    exit(-1);
  }
}
/*****************************************/

// Setup a Unix domain socket to listen on
int setup() {
  int socket_fd;
  int result;
  struct sockaddr_un addr;
  char *socket_path = "/tmp/pinger/pinger_socket";
  
  // Linux controls socket file permissions based on the permissions of the
  // directory that contains the socket file, not via direct permission
  // settings
  // So, create a directory with the proper permissions
  umask(0000);
  if (mkdir("/tmp/pinger/", 0777)) {
    if (errno != EEXIST) { // If the error is that it already exists ->no prob
      perror("Can't create directory to locate socket");
      exit(-1);
    }
  }
  chmod("/tmp/pinger/", 0777);

  // Delete the socket file, if left over from previous runs
  if( access( socket_path, F_OK ) != -1 ) {
    if ( (result = unlink(socket_path) == -1) ) {
      perror("Can't delete previous socket file");
      exit(-1);
    }
  }
  
  if ( (socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket creation error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr)); // Clean a sockaddr_un struct
  addr.sun_family = AF_UNIX; // Set family
  // set socket's path
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
  // bind to the socket
  if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("Socket bind error");
    exit(-1);
  }
  // make the socket non-blocking
  socket_non_block(socket_fd);
  return socket_fd;
}
/*****************************************/

int main (int argc, char const *argv[])
{
  char          *dest;
  const char    *source, *source_v4, *source_v6;
  struct tr_conf    *conf;  /* configuration defaults */

  struct sockaddr   *from, *to;
  struct addrinfo    hints, *res, *src_ip;
  const char  *hostname = NULL;
  char ch;
  int error;
  char  hbuf[NI_MAXHOST];

  int socket_fd, fd;
  int new_fd = 0;
  FILE *file;
  
  struct sockaddr_in   from4, to4;
  struct sockaddr_in6  from6, to6;

  
  int sndsock;  /* send socket file descriptor */
  
  int sndsock4, sndsock6;
  int v4sock_errno = 0;
  int v6sock_errno = 0;
  
  int v6flag = 0;
  int proto, flag;

  int file_input = 0;
  
  conf = calloc(1, sizeof(struct tr_conf));
  conf->incflag = 1;
  conf->first_ttl = 1;
  conf->proto = IPPROTO_UDP;
  conf->max_ttl = 32;
  // conf->max_ttl = IPDEFTTL;
  conf->nprobes = 3;
  
	conf->port = 33434;
	conf->ident = 666;
	
  char buffer[128];
  char *progname = basename((char *)argv[0]);
  
  char *input_f;
  char *lineptr;
  lineptr = calloc(256, 1);
  
  while ((ch = getopt(argc, (char * const *)argv, "df:h6ti")) != (char)-1) {
    // char *optarg;
    switch (ch) {
      case 'h':
        usage(progname);
        break;
      case 'd':
        is_daemon = 1;
        break;
      case 'f': // name of input file or socket (if in is_daemon mode)
        input_f = optarg;
        file_input = 1;
        break;
      case '6':
        v6flag = 1;
        break;
      case 'i':
        conf->proto = IPPROTO_ICMP;
        break;
      case 't':
          conf->proto = IPPROTO_TCP;
          break;
      default:
        ;
    }
  }

  argc -= optind;
  argv += optind;

  if (is_daemon == 0 && file_input == 0) {
    if (argc < 1 || argc > 3)
      usage(progname);
    dest = (char *)*argv;    
  }

  source_v4 = "172.104.147.241"; // testbed-de
  source_v6 = "2a01:7e01::f03c:91ff:fed5:395"; // testbed-de
  
  // Open file or socket
  if (file_input) {
    if (is_daemon) {
      socket_fd = setup();
      // Start listening on socket
      if (listen(socket_fd, SOMAXCONN) == -1) {
        perror("Socket listen error");
        exit(-1);
      }
      while (new_fd <=0) {
        new_fd = accept(socket_fd, NULL, NULL);
        if (new_fd == -1) {
          if (errno == EAGAIN) {
            continue;
          } else {
            perror("Error accepting socket");
            exit(-2);
          }
        } else {
          printf("Accepted new connection\n");
        }
      }
    } else {
      file = fopen(input_f, "r");
      if (file == NULL) {
        perror("Input file error");
        printf("File: %s\n", input_f);
        exit(-1);
      }
    }
  }
  
  do {
    if (file_input) {
      if (is_daemon) {
        if (read(new_fd, buffer, sizeof(buffer)) == -1) {
          if (errno == EAGAIN) {
            continue;
          }
          perror("Error reading from socket");
        }
        printf("read new data: %s\n", buffer);
        dest = buffer+6; // address starts at string position 6
        *(buffer+5) = 0; // Null terminate at position 6 for atoi below
        conf->port = atoi(buffer);
        fprintf(stderr, "Address: %s, Port: %d\n", dest, conf->port);
      } else {
        size_t n = 256;
        ret = getline(&lineptr, &n, file);
        if (ret == -1) {
          exit(0);
        }
        dest = strtok(lineptr, ","); // first item in the line is the IP address
        conf->port = atoi(strtok(NULL,",")); // and the port comes after the comma
        if (ret != 2) {
          printf("dest: %s, port: %d\n", dest, conf->port);
        }
      }
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_RAW;
    hints.ai_flags = AI_CANONNAME;
    if ((error = getaddrinfo(dest, NULL, &hints, &res)))
      errx(1, "%s", gai_strerror(error));
    if (res->ai_family == AF_INET) {
      source = source_v4;
      hints.ai_family = AF_INET;
      v6flag = 0;
    } else if (res->ai_family == AF_INET6) {
      source = source_v6;
      hints.ai_family = AF_INET6;
      v6flag = 1;
    } else {
      errx(1, "Unknown address family\n");
    }
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
      errx(1, "Unsupported AF: %d", res->ai_family);
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

    if (v6flag) {
      #ifdef IPV6_PKTINFO
          proto = IPPROTO_IPV6;
          flag = SSO_IPV6_RECVPKTINFO;
      #endif
          if ((sndsock6 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        v6sock_errno = errno;
      }

      if (v6sock_errno != 0) {
        perror("");
        errx(5, "socket(SOCK_DGRAM)");
      }

      sndsock = sndsock6;
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
    
      if ((sndsock4 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        v4sock_errno = errno;
        perror("Can't open send socket");
      }

      if (v4sock_errno != 0) {
        errx(5, "raw socket");
        }
      
        sndsock = sndsock4;
    }

    printf("Send socket: %d\n", sndsock);
    int seq = 0;
    int ttl = 1;
    char addr_str[256];
    if (v6flag) {
      printf("Sending probe to %s, %s\n", hostname, inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)to)->sin6_addr), addr_str, 256));
    } else {
      printf("Sending probe to %s, %s\n", hostname, inet_ntop(AF_INET, &(((struct sockaddr_in *)to)->sin_addr), addr_str, 256));    
    }

    for (ttl = conf->first_ttl; ttl < conf->max_ttl; ttl++) {
      send_probe(conf, sndsock, seq, ttl, to, from);
      // send_probe(conf, sndsock, seq, 64, to, from);
    }

    freeaddrinfo(res);
  } while(file_input);
  
  return 0;
}

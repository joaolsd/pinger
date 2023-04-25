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
#include "sender.h"
#include "util.h"

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

#define LINEBUF_SIZE 128 

int is_daemon = 0;
int debug = 0;
int ret = 0;

/*****************************************/
void usage(char *progname) {
  printf("pinger [-f <filename>] [-d] [-h] [-6] [-t] [-i] [\"probe data\"]");
  printf("-f: path to an input file or unix socket\n");
  printf("-d: daemonise (must use a socket to send input)\n");
  printf("-i: use ICMP\n");
  printf("-t: use TCP\n");
  printf("-h: this help\n");
  printf("-x: Turn on debugging\n");
  printf("data:\n");
  printf("  addr_family,target addr,protocol,options\n");
	exit(0);
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
void parse_input_line(char *str, struct probe* probe)
{
  char *dst_addr, *options;
  struct addrinfo hints, *res, *src_ip;
  int error;
  // 4,192.168.1.1,u,options
  // 1st field: 4 or 6, for IPv4/IPv6
  // 2nd field: IPv(4|6) address
  // 3rd field: protocol (u:udp, t:tcp, i:icmp)
  // 4th field: initial TTL/hop count
  // 5th field: final TTL/hop count
  // 6th field: options (e.g. extension header for IPv6)
  probe->addr_family = str[0]-'0'; // first field, single char is a 4 or 6
  dst_addr = strtok(str+2, ","); // 2nd field is the IP address
  probe->protocol = *(strtok(NULL,",")); // transport protocol
  probe->initial_ttl = atoi(strtok(NULL,","));
  probe->final_ttl = atoi(strtok(NULL,","));
  options = strtok(NULL,","); // extension header, if any

  switch (probe->protocol) {
    case 'u':
    case 'U':
      probe->protocol = IPPROTO_UDP;
      break;
    case 't':
    case 'T':
      probe->protocol = IPPROTO_TCP;
      break;
    case 'i':
    case 'I':
      if (probe->addr_family == 4) {
      probe->protocol = IPPROTO_ICMP;
      }  
      if (probe->addr_family == 6) {
      probe->protocol = IPPROTO_ICMPV6;
      }
      break;
    default:
      errx(1, "Unknown protocol in input line: %d\n", probe->protocol);
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_RAW;
  hints.ai_flags = AI_CANONNAME;
  if ((error = getaddrinfo(dst_addr, NULL, &hints, &res))) {
    errx(1, "%s", gai_strerror(error));
  }
  if ((res->ai_family == AF_INET && probe->addr_family != 4) || \
      (res->ai_family == AF_INET6 && probe->addr_family != 6)) {
        errx(1, "Mismatch between address family and address\n");
  }
  if (probe->addr_family == 4) {
  memcpy(&(probe->dst_addr), &(((struct sockaddr_in *)(res->ai_addr))->sin_addr), sizeof(struct in_addr));
  } else {
    memcpy(&(probe->dst_addr), &(((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr), sizeof(struct in6_addr));
  }

  if (debug) {
    char * hostname;
    char * hbuf;
      hostname = res->ai_canonname ? strdup(res->ai_canonname) : dst_addr;
      if (!hostname) {
        printf("malloc error for hostname");
        freeaddrinfo(res);
        return;
      }
      printf("Hostname: %s\n", hostname);
    if (res->ai_next) {
      if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
          sizeof(hbuf), NULL, 0, NI_NUMERICHOST) != 0) {
        strncpy(hbuf, "?", sizeof(hbuf));
        warnx("Warning: %s has multiple "
          "addresses; using %s", hostname, hbuf);
      }
    }
  }

  // Process options
  strncpy((char *)&(probe->options), options, sizeof(probe->options));
  freeaddrinfo(res);
}
/*****************************************/
int open_v6_socket() {
  int send_socket;
  int proto, flag;
  int sock_errno = 0;

#ifdef IPV6_PKTINFO
  proto = IPPROTO_IPV6;
  flag = SSO_IPV6_RECVPKTINFO;
#endif
  if ((send_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    sock_errno = errno;
  }

  if (sock_errno != 0) {
    perror("");
    errx(5, "socket(SOCK_DGRAM)");
  }

  return send_socket;
}
/*****************************************/
int open_v4_socket() {
  int send_socket;
  int proto, flag;
  int sock_errno = 0;
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

  if ((send_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    sock_errno = errno;
    perror("Can't open send socket");
  }

  if (sock_errno != 0) {
    errx(5, "raw socket");
  }

  return send_socket;
}
/*****************************************/
void socket_non_block (int socket) {
  // Make socket non-blocking
  int flags, s;
  flags = fcntl(socket, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl error");
    exit(-1);
  }
  flags |= O_NONBLOCK; // Add non-blocking flag
  s = fcntl(socket, F_SETFL, flags);
  if (s == -1) {
    perror("fcntl error");
    exit(-1);
  }
}
/*****************************************/
// Setup a Unix domain socket to listen on
int setup_unix_socket() {
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
  const char      *source_v4_str, *source_v6_str;
  struct tr_conf  *conf;  /* configuration defaults */

  struct addrinfo hints, *src_ip;
  const char     *hostname = NULL;
  char ch;
  int error;
  char  hbuf[NI_MAXHOST];

  int send_socket_v4, send_socket_v6;
  int socket_fd, fd;
  int new_fd = 0;
  FILE *file;
  FILE *log_f = stdout;
  
  struct probe probe;

  struct in_addr  *source_v4;
  struct in6_addr *source_v6;

  source_v4 = malloc(sizeof(struct in_addr));
  source_v6 = malloc(sizeof(struct in6_addr));
  
  int sndsock;  /* send socket file descriptor */
  int proto, flag;
  int file_input = 0;
  
  // default values
  conf = calloc(1, sizeof(struct tr_conf));
  conf->first_ttl = 1;
  conf->proto = IPPROTO_UDP;
  conf->max_ttl = 32;
  // conf->max_ttl = IPDEFTTL;
  conf->nprobes = 3;
  conf->if_name =  "eth0";
  // conf->if_name =  "enp0s2";
	conf->port = 443;
	conf->ident = 666;
	
  char *progname = basename((char *)argv[0]);
  
  char *input_f;
  char *log_file_name = NULL;
  char *lineptr;
  lineptr = calloc(LINEBUF_SIZE, 1);
  
  while ((ch = getopt(argc, (char * const *)argv, "df:hil:tx")) != (char)-1) {
    // char *optarg;
    switch (ch) {
      case 'h':
        usage(progname);
        break;
      case 'd':
        is_daemon = 1;
        break;
      case 'f': // name of input file or socket (if in daemon mode)
        input_f = optarg;
        file_input = 1;
        break;
      // case '6':
      //   v6flag = 1;
      //   break;
      case 'i':
        conf->proto = IPPROTO_ICMP;
        break;
      case 'l':
        log_file_name = optarg;
      case 't':
        conf->proto = IPPROTO_TCP;
        break;
      case 'x': // Debug flag
        debug = 1;
        break;
      default:
        usage(progname);
    }
  }

  // Non option argument
  // strncpy(lineptr, (char *)argv[optind], 128);

  // Initialise source addresses
  source_v4_str = "172.104.147.241"; // testbed-de
  source_v6_str = "2a01:7e01::f03c:91ff:fed5:395"; // testbed-de

  inet_pton(AF_INET, (char *)source_v4_str, source_v4);
  inet_pton(AF_INET6, (char *)source_v6_str, source_v6);
  // memset(&hints, 0, sizeof(hints));
  // hints.ai_socktype = SOCK_RAW;
  // hints.ai_protocol = IPPROTO_RAW;
  // // hints.ai_flags = AI_CANONNAME;
  // hints.ai_flags = AI_NUMERICHOST;
  // hints.ai_family = AF_INET;
  // if ((error = getaddrinfo(source_v4_str , NULL, &hints, &source_v4)))
  //   errx(1, "%s", gai_strerror(error));
  // hints.ai_family = AF_INET6;
  // if ((error = getaddrinfo(source_v6_str , NULL, &hints, &source_v6)))
  //   errx(1, "%s", gai_strerror(error));
  
  // Open log file
  if (log_file_name) {
    log_f = fopen(log_file_name, "a");
  }

  // Open file or socket
  if (file_input) {
    if (is_daemon) {
      daemonise();
      socket_fd = setup_unix_socket();
      // Start listening on socket
      if (listen(socket_fd, SOMAXCONN) == -1) {
        perror("Socket listen error");
        exit(-1);
      }

    } else {
      file = fopen(input_f, "r");
      if (file == NULL) {
        perror("Input file error");
        printf("File: %s\n", input_f);
        exit(-1);
      }
    }
  } else {
   file = stdin;
  }

  send_socket_v4 = open_v4_socket();
  send_socket_v6 = open_v6_socket();

  do {
    if (file_input) {
      if (is_daemon) {
        while (new_fd <=0) {
          new_fd = accept(socket_fd, NULL, NULL);
          if (new_fd == -1) {
            if (errno == EAGAIN) {
              continue;
            } else {
              perror("Error accepting socket");
              exit(-2);
            }
          }
        }
        if (read(new_fd, lineptr, LINEBUF_SIZE) == -1) {
          if (errno == EAGAIN) {
            continue;
          }
          perror("Error reading from socket");
        }
        if (debug) fprintf(log_f, "read new data: %s\n", lineptr);
      } else {
        size_t n = 128;
        ret = getline(&lineptr, &n, file);
        if (ret == -1) exit(0);
      }
    } else {
        size_t n = 128;
        ret = getline(&lineptr, &n, file);
        if (ret == -1) exit(0);
    }
    parse_input_line(lineptr,&probe);

    int seq = 0;
    int i_ttl, f_ttl, ttl;
    if (probe.initial_ttl != 0) {
      i_ttl = probe.initial_ttl;
    } else {
      i_ttl = conf->first_ttl;
    }
    if (probe.final_ttl != 0) {
      f_ttl = probe.final_ttl;
    } else {
      f_ttl = conf->max_ttl;
    }

    char addr_str[256];
    if (probe.addr_family == 6) {
      memcpy((void *)&(probe.src_addr), (void *)source_v6, sizeof(struct in6_addr));
      if (debug) {
        fprintf(log_f, "Sending probe to %s\n", inet_ntop(AF_INET6, &(probe.dst_addr), addr_str, 256));
      }
      sndsock = send_socket_v6;
    } else {
      memcpy((void *)&(probe.src_addr), (void *)source_v4, sizeof(struct in_addr));
      if (debug) {
        printf("Sending probe to %s\n", inet_ntop(AF_INET, &(probe.dst_addr), addr_str, 256));
      }
      sndsock = send_socket_v4;
    }

    for (ttl = i_ttl; ttl <= f_ttl; ttl++) {
      send_probe(conf, sndsock, seq, ttl, &probe, log_f);
    }

  } while(file_input);
  
  return 0;
}

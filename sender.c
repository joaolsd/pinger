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
#include <sys/stat.h>
#include <sys/un.h>
// #include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "sender.h"
#include "util.h"
#include <libgen.h>
#include <time.h>

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
FILE *log_f;

#define MAX_INPUT_LINES 50000
#define MAX_TTL_VALUES 32

struct probe prefixes[MAX_INPUT_LINES];
struct probes {
  int ttl;
  struct probe * prefix;
} probes[MAX_INPUT_LINES * MAX_TTL_VALUES];



extern uint8_t src_mac[6];
extern uint8_t dst_mac_v4[6];
extern uint8_t dst_mac_v6[6];

/*****************************************/
void usage(char *progname) {
  printf("pinger options");
  printf("  probe data comes from stdin or the -f argument]\n");
  printf("  and has the format:\n");
  printf("  addr_family,target addr,protocol,initial_ttl,final_ttl,options\n");
  printf("-4: The source IPv4 address to use\n");
  printf("-6: The source IPv6 address to use\n");
  printf("-a: sender (my) MAC address\n");
  printf("-b: gateway MAC address to use for v4 packets\n");
  printf("-c: gateway MAC address to use for v6 packets\n");
  printf("-d: daemonise (must use a socket to send input)\n");
  printf("-f: path to an input file, unix socket or IP_address:UDP_port\n");
  printf("-h: this help\n");
  printf("-i: ethernet interface to use for sending packets\n");
  printf("-p: protocol to use (t:tcp, i:icmp). default is UDP\n");
  printf("-x: Turn on debugging\n");
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
void parse_options(char * options, struct probe* probe) {
  char *option;
  char *saveptr;
  // Options are separated by ';'
  option = strtok_r(options, ";", &saveptr);
  while (option != NULL) {
    if (debug) printf("probe options: %s\n", options);
    switch (option[0]) { // first char after delimiter
      case 'E': // IPv6 extension header
        switch (option[1]) {
          case 'H': // Hop by hop
            probe->v6_options.type = NEXTHDR_HOP;
            probe->v6_options.size = atoi(&option[2]);
            if (debug) printf("  HBH EH\n");
            break;
          case 'D': // Destination
            probe->v6_options.type = NEXTHDR_DEST;
            probe->v6_options.size = atoi(&option[2]);
            if (debug) printf("  DEST EH\n");
            break;
          default:
            probe->v6_options.type = 0;
            break;
        }
        break;
      default:
        probe->v6_options.type = NEXTHDR_NONE;
        return;
    }
    option = strtok_r(NULL, ";", &saveptr);
  };
}

/*****************************************/
int parse_input_line(char *str, struct probe* probe) {
  char *dst_addr, *options;
  struct addrinfo hints, *res, *src_ip;
  int error;
  struct sockaddr addr_in;
  // 4,192.168.1.1,u,options
  // 1st field: 4 or 6, for IPv4/IPv6
  // 2nd field: IPv(4|6) address
  // 3rd field: protocol (u:udp, t:tcp, i:icmp)
  // 4th field: initial TTL/hop count
  // 5th field: final TTL/hop count
  // 6th field: options (e.g. extension header for IPv6)
  probe->addr_family = str[0]-'0'; // first field, single char is a 4 or 6
  dst_addr = strtok(str+2, ","); // 2nd field is the IP address
  // Check for valid IPv4 or IPv6 address
  if (probe->addr_family == 4) {
    if (!inet_pton(AF_INET, dst_addr, (void * restrict) &addr_in)) return 0;
  } else if (probe->addr_family == 6) {
    if (!inet_pton(AF_INET6, dst_addr, (void * restrict) &addr_in)) return 0;
  } else {
    return 0;
  }
  probe->protocol = *(strtok(NULL,",")); // transport protocol
  probe->initial_ttl = atoi(strtok(NULL,","));
  if (probe->initial_ttl < 0 || probe->initial_ttl > 255) return 0;
  probe->final_ttl = atoi(strtok(NULL,","));
  if (probe->final_ttl < 0 || probe->final_ttl > 255) return 0;
  if (probe->final_ttl < probe->initial_ttl) return 0;
  options = strtok(NULL,","); // extension header, if any
  parse_options(options, probe);

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
      return 0;
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
        return 0;
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

  freeaddrinfo(res);
  return 1;
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
// Setup a UDP socket to listen on
int setup_udp_socket(char *hostport) {
  char *port;
  char *hostname;
  struct addrinfo hints, *res, *p;
  int sockfd;
  int status;
  char ipstr[INET6_ADDRSTRLEN];
  int fd_count;

  int yes = 1;
  
  char *token = strchr(hostport, ':');
  if (token == NULL) {
    printf("Invalid string format\n");
    return 1;
  }
  *token = '\0'; // replace ':' with null character to split the string
  hostname = hostport; // first part of string is the  host
  port = token + 1; // second part is the port

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol=0;
  hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG; // fill in my IP for me

  if ((status = getaddrinfo(hostname, port, &hints, &res)) != 0) {
      fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
      return 1;
  }

  p = res; // use only the first item in the response even if there are more
  void *addr;
  char *ipver;

  // get the pointer to the address itself,
  // different fields in IPv4 and IPv6:
  if (p->ai_family == AF_INET) { // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
  } else { // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
  }

  // create a socket:
  sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
  if (sockfd < 0) {
      perror("socket");
      exit(1);
  }

  // set socket options to allow reuse of address:
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
  }

  // bind the socket to the address:
  if (bind(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
      close(sockfd);
      perror("Error while binding");
      exit(1);
  }

  // listen on the socket:
  // if (listen(sockfd, 10) < 0) {
  //     close(sockfd);
  //     perror("Error while trying to listen");
  //     exit(1);
  // }
  inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
  if (debug) fprintf(log_f, "Socket bound and listening on %s:%s\n", ipstr, port);

  freeaddrinfo(res);
  return sockfd;
}


/*****************************************/
// Setup a Unix domain socket to listen on
int setup_unix_socket(char *input_f) {
  int socket_fd;
  int result;
  struct sockaddr_un addr;
  char socket_path[256];
  struct stat statbuf;

  if (stat(input_f, &statbuf) == 0) {
    if (statbuf.st_mode & S_IFMT == S_IFSOCK) {
      strncpy(socket_path, input_f, sizeof(socket_path));
    } else { // default path for socket
      strcpy(socket_path,"/tmp/pinger/pinger_socket");
    }
  }
  // Linux controls socket file permissions based on the permissions of the
  // directory that contains the socket file, not via direct permission
  // settings
  // So, create a directory with the proper permissions

  char *dir_name = dirname(socket_path);
  // char *base_name = basename(socket_path);
  umask(0000);
  if (mkdir(dir_name, 0777)) {
    if (errno != EEXIST) { // If the error is that it already exists ->no prob
      perror("Can't create directory to locate socket");
      exit(-1);
    }
  }
  chmod(dir_name, 0777);

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
  // Start listening on socket
  if (listen(socket_fd, SOMAXCONN) == -1) {
    perror("Socket listen error");
    exit(-1);
  }

  return socket_fd;
}
/*****************************************/
int main (int argc, char const *argv[])
{
  char *source_v4_str, *source_v6_str;
  char *interface;
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
  
  struct probe probe;

  struct in_addr  *source_v4;
  struct in6_addr *source_v6;
  char addr_str[256];

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
	conf->port = 443;
	conf->ident = 666;
	
  char *progname = basename((char *)argv[0]);
  
  char *input_f;
  char *log_file_name = NULL;
  char *lineptr;
  int udp_socket;

  int src_mac_set = 0;
  int dst_mac_set_v4 = 0;
  int dst_mac_set_v6 = 0;

  log_f = stdout; // default
  lineptr = calloc(LINEBUF_SIZE, 1);
  
  // Initialise default source addresses
  source_v4_str = "172.104.147.241"; // testbed-de
  source_v6_str = "2a01:7e01::f03c:91ff:fed5:395"; // testbed-de
  interface = "eth0"; // outgoing interface

  while ((ch = getopt(argc, (char * const *)argv, "4:6:a:b:c:df:hi:l:p:x")) != (char)-1) {
    // char *optarg;
    switch (ch) {
      case '4':
        source_v4_str = strdup(optarg);
        break;
      case '6':
        source_v6_str = strdup(optarg);
        break;
      case 'a':
        // mac address of our ethernet interface
        if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
        }
        src_mac_set = 1 ;
        break;
      case 'b':
        // mac address of V4 gateway to the Internet
        if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac_v4[0], &dst_mac_v4[1], &dst_mac_v4[2], &dst_mac_v4[3], &dst_mac_v4[4], &dst_mac_v4[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
        }
        dst_mac_set_v4 = 1 ;
        break;
      case 'c':
        // mac address of V6 gateway to the Internet
        if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac_v6[0], &dst_mac_v6[1], &dst_mac_v6[2], &dst_mac_v6[3], &dst_mac_v6[4], &dst_mac_v6[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
        }
        dst_mac_set_v6 = 1 ;
        break;
      case 'h':
        usage(progname);
        break;
      case 'd':
        is_daemon = 1;
        break;
      case 'i':
        conf->if_name = strdup(optarg);
        break;
      case 'f': // name of input file or socket (if in daemon mode)
        input_f = optarg;
        file_input = 1;
        break;
      // case '6':
      //   v6flag = 1;
      //   break;
      case 'l':
        log_file_name = optarg;
      case 'p':
        if (strcmp(optarg, "t")) {
          conf->proto = IPPROTO_TCP;
        } else if (strcmp(optarg, "i")) {
          conf->proto = IPPROTO_ICMP;
        } else {
          perror("Unknown protocol with -p");
          exit(1);
        }
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

  // Check if src mac is set and warn if not
  if (!src_mac_set) {
    perror("warning: source mac address not set");
  }
  // If we only set one dst mac addr, copy over to the other
  if (dst_mac_set_v4 && !dst_mac_set_v6) {
    memcpy(dst_mac_v6, dst_mac_v4, 6);
  }
  if (!dst_mac_set_v4 && dst_mac_set_v6) {
    memcpy(dst_mac_v4, dst_mac_v6, 6);
  }

  if (inet_pton(AF_INET, (char *)source_v4_str, source_v4)  != 1) {
    perror("Invalid IPv4 source address");
    exit(1);
  }
  if (inet_pton(AF_INET6, (char *)source_v6_str, source_v6) != 1) {
    perror("Invalid IPv6 source address");
    exit(1);
  }
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
    if (log_f == NULL) {
      perror("Can't open log file");
      exit(1);
    }
  }

  // Open file or socket
  if (file_input) {
    if (is_daemon) {
      daemonise();
      if (strchr(input_f, ':') != NULL) { // hostname:port?
        socket_fd = setup_udp_socket(input_f);
        udp_socket = 1;
      } else { // assume it is a local path to a UNIX socket
        socket_fd = setup_unix_socket(input_f);
        udp_socket = 0;
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

  int seq = 0;
  if (file_input & !is_daemon) { // when reading from a file, read the entire file and shuffle elements to avoid rate limiting
    size_t n = LINEBUF_SIZE;
    int t;
    int n_lines = 0;
    int cursor1 = 0;
    int cursor2 = 0;
    int ttl;
    srand(time(0));

    while(1) {
      ret = getline(&lineptr, &n, file);
      if (ret == -1) break;

      // 4,192.168.1.1,u,options
      // 1st field: 4 or 6, for IPv4/IPv6
      // 2nd field: IPv(4|6) address
      // 3rd field: protocol (u:udp, t:tcp, i:icmp)
      // 4th field: initial TTL/hop count
      // 5th field: final TTL/hop count
      // 6th field: options (e.g. extension header for IPv6)
      if (!parse_input_line(lineptr,&probe)) {
        continue;
      }
      memcpy(&prefixes[n_lines], &probe, sizeof(struct probe)); // store input data in vector of prefixes
      cursor2 = cursor1 + (probe.final_ttl - probe.initial_ttl);
      ttl = probe.initial_ttl;
      for (t = cursor1; t < cursor2; t++) {
        printf("cursor1: %d, cursor2:%d, t:%d\n", cursor1, cursor2, t);
        probes[t].ttl = ttl;  // vector storing prefix and TTL
        probes[t].prefix = &prefixes[n_lines];
        ttl++;
      }
      n_lines++;
      if (n_lines > MAX_INPUT_LINES) {
        fprintf(stderr, "File too long: Maxmimum line count reached, exiting\n");
        exit(1);
      }
      cursor1 = cursor2;
    };
  
    // for (int i = 0; i < n_lines; i++) {
    //   printf("i: %d,",i);
    //   printf("Addr family: %d, ", prefixes[i].addr_family);
    //   printf("dest addr: %s", inet_ntop(AF_INET6, &(prefixes[i].dst_addr), addr_str, 256));
    //   printf("Protocol: %d", prefixes[i].protocol);
    //   printf("TTLs: %d, %d, %d\n", ttl, prefixes[i].initial_ttl, prefixes[i].initial_ttl);
    //   // printf("Options type %d and size %d\n", prefixes[i].v6_options.type, prefixes[i].v6_options.size);
    // }
    // shuffle list of probes
    struct probe temp;
    for (int i = cursor2 - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        memcpy(&temp, &probes[i], sizeof(struct probes));
        memcpy(&probes[i],&probes[j], sizeof(struct probes));
        memcpy(&probes[j], &temp, sizeof(struct probes));
    }

    // for (int i = cursor2 - 1; i >= 0; i--) {
    //   printf("i: %d, ",i);
    //   printf("Addr family: %d, ", probes[i].prefix->addr_family);
    //   printf("dest addr: %s\n", inet_ntop(AF_INET6, &(probes[i].prefix->dst_addr), addr_str, 256));
    //   printf("Protocol: %d\n", probes[i].prefix->protocol);
    //   printf("TTLs: %d, %d, %d\n", probes[i].ttl, probes[i].prefix->initial_ttl, probes[i].prefix->final_ttl);
    //   // printf("Options: %s\n", probes[i].prefix->v6_options);
    // }

    // Loop over data from file
    for (int i = 0; i < cursor2; i++) {
      ttl = probes[i].ttl;
      memcpy(&probe, probes[i].prefix, sizeof(struct probe));
      // printf("Addr family: %d\n", probes[i].prefix->addr_family);
      // printf("Options: %s\n", probes[i].prefix->v6_options);
      // printf("Protocol: %d\n", probes[i].prefix->protocol);
      // printf("TTLs: %d, %d, %d\n", ttl, probes[i].prefix->initial_ttl, probes[i].prefix->initial_ttl);
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

        send_probe(conf, sndsock, seq, ttl, &probe, log_f);
    }
  } else { // reading from socket or stdin
    do {
      if (file_input) {
        if (is_daemon) {
          if (udp_socket == 0) {
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
          } else {
            new_fd = socket_fd;
          }
          if (read(new_fd, lineptr, LINEBUF_SIZE) == -1) {
            if (errno == EAGAIN) {
              continue;
            }
            perror("Error reading from socket");
          }
          if (debug) fprintf(log_f, "read new data: %s\n", lineptr);
        }
      } else { //read from stdin
          size_t n = LINEBUF_SIZE;
          ret = getline(&lineptr, &n, file);
          if (ret == -1) exit(0);
      }
      new_fd = 0;
      // 4,192.168.1.1,u,options
      // 1st field: 4 or 6, for IPv4/IPv6
      // 2nd field: IPv(4|6) address
      // 3rd field: protocol (u:udp, t:tcp, i:icmp)
      // 4th field: initial TTL/hop count
      // 5th field: final TTL/hop count
      // 6th field: options (e.g. extension header for IPv6)
      if (!parse_input_line(lineptr,&probe)) {
        continue;
      }

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
  }
  return 0;
}

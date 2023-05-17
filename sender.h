#ifndef SENDER_H
#define SENDER_H

#include <netinet/in.h>

extern int debug;

struct v6_options {
  u_int8_t type;
  u_int8_t size;
};

struct probe {
  int addr_family;
  struct in6_addr dst_addr; // make space for the bigger of the addresses (IPv6)
  struct in6_addr src_addr;
  int initial_ttl;
  int final_ttl;
  char protocol;
  struct v6_options v6_options;
};
void usage(char *progname);
#endif // SENDER_H
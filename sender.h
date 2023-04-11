#ifndef SENDER_H
#define SENDER_H

#include <netinet/in.h>

extern int debug;

struct probe {
  int addr_family;
  struct in6_addr dst_addr; // make space for the bigger of the addresses (IPv6)
  struct in6_addr src_addr;
  int initial_ttl;
  int final_ttl;
  char protocol;
  char options[32];
};
void usage(char *progname);
#endif // SENDER_H
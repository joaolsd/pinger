void print_tcp_header_with_pseudo_header(const u_char *buffer);
void print_tcp_header(const u_char *buffer);
void print_udp_header(const u_char * buffer);
void print_icmp6_header(const u_char * buffer);
void print_icmp_header(const u_char *buffer);
void print_ipv6_header(const u_char *buffer);
void print_ipv4_header(const u_char *buffer);
void print_ethernet_header(const u_char *buffer);
void Hexdump(const void* data, size_t size);
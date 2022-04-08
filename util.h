struct tr_conf {
	int		 incflag;	/* Do not inc the dest. port num */
	int		 first_ttl;	/* Set the first TTL or hop limit */
	u_char		 proto;		/* IP payload protocol to use */
	u_int8_t	 max_ttl;	/* Set the maximum TTL / hop limit */
	int		 nprobes;
	u_int16_t 	 port;		/* start udp dest port */
	int		 waittime;	/* time to wait for a response */
	int		 Aflag;		/* lookup ASN */
	int		 dflag;		/* set SO_DEBUG */
	int		 dump;
	int		 protoset;
	int		 ttl_flag;	/* display ttl on returned packet */
	int		 nflag;		/* print addresses numerically */
	char		*source;
	int		 sump;
	int		 tos;
	int		 tflag;		/* tos value was set */
	int		 verbose;
	u_int		 rtableid;	/* Set the routing table */
	u_short		 ident;
};

/*
 * Format of the data in a (udp) probe packet.
 */
struct packetdata {
	u_char seq;		/* sequence number of this packet */
	u_int8_t ttl;		/* ttl packet left with */
	u_char pad[2];
	u_int32_t sec;		/* time packet left */
	u_int32_t usec;
};

uint16_t checksum(uint16_t *buffer, int size);
uint16_t tcp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr);
uint16_t udp_checksum_ipv4(const void *buff, size_t len, size_t length, in_addr_t *src_addr, in_addr_t *dest_addr);
uint16_t icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr, uint8_t *payload, int payloadlen);

void ether_header(int IP_v, uint8_t *outpacket);

void build_probe4(struct tr_conf *conf, int seq, u_int8_t ttl, uint8_t *outpacket, struct sockaddr_in *to, struct sockaddr_in *from);
void build_probe6(struct tr_conf *conf, int seq, u_int8_t hops, uint8_t *outpacket, struct sockaddr_in6 *to, struct sockaddr_in6 *from, int sndsock);
void send_probe(struct tr_conf *conf, int sndsock, int seq, u_int8_t ttl, struct sockaddr *to, struct sockaddr *from);

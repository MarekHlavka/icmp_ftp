#ifndef ICMP_PACKET
#define ICMP_PACKET

int open_icmp_socket();

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp);

#endif //ICMP_PACKET
#ifndef ICMP
#define ICMP

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

struct icmp_packet
{
	char src_addr[100];
	char dest_addr[100];
	int type;
	char* payload;
	int payload_size;
};

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp);

#endif // ICMP
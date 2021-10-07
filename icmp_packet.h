#ifndef ICMP_PACKET
#define ICMP_PACKET

#include <stdint.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MTU 			1500
#define MAX_PYLD_SIZE 	(MTU - sizeof(struct iphdr) - sizeof(struct icmphdr) - sizeof(struct s_icmp_file_info))
#define MAX_FILENAME 	32

struct icmp_packet
{
	char src_addr[100];
	char dest_addr[100];
	int type;
	char* payload;
	int payload_size;
	uint8_t file_type;
	uint16_t order;
	char filename[MAX_FILENAME];
};

struct s_icmp_file_info
{
	uint8_t type;
	uint16_t order;
	char filename[MAX_FILENAME];
};

int open_icmp_socket();

void bind_icmp_socket(int sock_id);

void set_echo_type(struct icmp_packet *packet);

void set_reply_type(struct icmp_packet *packet);

void send_icmp_packet(int sock_id, struct icmp_packet *packet_details);

void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details);

void close_icmp_socket(int socket_id);

#endif //ICMP_PACKET
#ifndef ICMP_PACKET
#define ICMP_PACKET

struct icmp_packet
{
	char src_addr[100];
	char dest_addr[100];
	int type;
	char* payload;
	int payload_size;
};

int open_icmp_socket();

void bind_icmp_socket(int sock_id);

#endif //ICMP_PACKET
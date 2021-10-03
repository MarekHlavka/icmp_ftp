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

void set_echo_type(struct icmp_packet *packet);

void set_reply_type(struct icmp_packet *packet);

void send_icmp_packet(int sock_id, struct icmp_packet *packet_details);

void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details);

void close_icmp_socket(int socket_id);

#endif //ICMP_PACKET
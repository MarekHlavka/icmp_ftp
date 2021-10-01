#include "icmp_packet.h"
#include <string.h>

int main(){
	struct icmp_packet packet;
	char *src_ip;
	char *dst_ip;
	int socket_id;

	src_ip = "127.0.0.2";
	dst_ip = "127.0.0.1";

	strncpy(packet.src_addr, src_ip, strlen(src_ip) + 1);
	strncpy(packet.dest_addr, dst_ip, strlen(src_ip) + 1);

	//set_reply_type(&packet);
	packet.payload = "Hello there!";
	packet.payload_size = strlen(packet.payload);

	socket_id = open_icmp_socket();
	printf("%d\n", socket_id);

	//send_icmp_socket(socket_id, &packet);

	//close_icmp_socket(socket_id);
}
#include "icmp_packet.h"

#include <stdio.h>
#include <string.h>

int main(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	printf("Server initialized...\n");
	while(1){
		recieve_icmp_packet(socket_id, &packet);
		printf("%s\n", packet.src_addr);
		printf("%s\n", packet.dest_addr);
		printf("%s\n", packet.type);
		printf("%s\n", packet.payload);
	}
	close_icmp_socket(socket_id);
}
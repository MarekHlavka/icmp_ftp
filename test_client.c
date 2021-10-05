#include "icmp_packet.h"
#include <string.h>
#include <stdio.h>


int main(int argc, char** argv){

	if(argc >= 2){
		struct icmp_packet packet;
		char *src_ip;
		char *dst_ip;
		int socket_id;

		src_ip = "127.0.0.2";
		dst_ip = "127.0.0.1";

		strncpy(packet.src_addr, src_ip, strlen(src_ip) + 1);
		strncpy(packet.dest_addr, dst_ip, strlen(src_ip) + 1);

		set_reply_type(&packet);
		packet.payload = "Hello there!";
		packet.payload_size = strlen(packet.payload);
		printf("%d\n", packet.payload_size);

		socket_id = open_icmp_socket();
		printf("%d\n", socket_id);

		printf("Sending...\n");
		send_icmp_packet(socket_id, &packet);
		printf("Closing...\n");
		close_icmp_socket(socket_id);
	}
	else{
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

}
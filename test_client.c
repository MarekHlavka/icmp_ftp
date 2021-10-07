#include "icmp_packet.h"
#include "file_handle.h"
#include "packet_handle.h"

#include <string.h>
#include <stdio.h>

#define ACTUAL_IP 		"100.69.161.11"

int main(int argc, char** argv){

	if(argc == 2){
		struct icmp_packet packet;
		char *src_ip;
		char *dst_ip;
		int socket_id;
		int packet_count;


		src_ip = "127.0.0.2";
		dst_ip = "127.0.0.1";

		strncpy(packet.src_addr, src_ip, strlen(src_ip) + 1);
		strncpy(packet.dest_addr, dst_ip, strlen(src_ip) + 1);

		char filename[MAX_FILENAME] = "file.txt";

		set_reply_type(&packet);
		packet.payload = read_file_as_byte_array(filename);
		packet_count = 1;

		packet.payload_size = strlen(packet.payload);
		packet.file_type = 1;
		packet.order = 0;
		memcpy(packet.filename, filename, sizeof(filename));



		char **buff = divide_payload(packet.payload, packet.payload_size,
			MAX_PYLD_SIZE/10, &packet_count);

		packet.payload = buff[1];

		printf("%d\n", packet_count);

		socket_id = open_icmp_socket();

		printf("Sending...\n");
		send_icmp_packet(socket_id, &packet);
		printf("Closing...\n");
		close_icmp_socket(socket_id);
	}
	else{
		if(argc == 1){
			struct icmp_packet packet;
			int socket_id;

			socket_id = open_icmp_socket();
			bind_icmp_socket(socket_id);

			printf("Server initialized...\n");
			while(1){
				recieve_icmp_packet(socket_id, &packet);
				printf("SRC:		%s\n", packet.src_addr);
				printf("DEST:		%s\n", packet.dest_addr);
				printf("TYPE:		%d\n", packet.type);
				printf("FILETYPE:	%d\n", packet.file_type);
				printf("ORDER:		%d\n", packet.order);
				printf("FILENAME:	%s\n", packet.filename);
				printf("Payload:\n%s\n", packet.payload);
			}
			close_icmp_socket(socket_id);
		}
		// AES testing
		else{

			return 0;

		}
	}

}
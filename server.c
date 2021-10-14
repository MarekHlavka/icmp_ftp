#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	unsigned char **buff = NULL;
	int packet_count = 0;
	int last_size = 0;
	int out_size = 0;

	//printf("Server initialized...\n");
	while(1){
		printf("-----------------------------------------------\n");
		recieve_icmp_packet(socket_id, &packet);

		if(buff == NULL){
			buff = (unsigned char **)malloc(packet.count * MAX_PYLD_SIZE * sizeof(unsigned char));
			if(buff == NULL){
				perror("No memory available 1\n");
				close_icmp_socket(socket_id);
				exit(-1);
			}
		}

		buff[packet.order] = (unsigned char *)malloc(packet.part_size * sizeof(unsigned char));
		if(buff[packet.order] == NULL){
				perror("No memory available 2\n");
				close_icmp_socket(socket_id);
				exit(-1);
		}

		memcpy(buff[packet.order], packet.payload, packet.part_size);
		packet_count++;
		if(packet.order == packet_count -1){
			last_size = packet.part_size;
		}

		//printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		//printf("SRC:		%s\n", packet.src_addr);
		//printf("DEST:		%s\n", packet.dest_addr);
		//printf("TYPE:		%d\n", packet.type);
		//printf("FILETYPE:	%d\n", packet.file_type);
		//printf("ORDER:		%d\n", packet.order);
		//printf("FILENAME:	%s\n", packet.filename);

		//printf("Encrypt:\n");
		if(packet.count == packet_count){
			break;
		}
	}

	printf("%d\n", packet_count);

	for(int i = 0; i < packet_count; i++){
		if(i == packet_count -1){
			out_size = last_size;
		}
		else{
			out_size = MAX_PYLD_SIZE;
		}
		BIO_dump_fp (stdout, (const char *)buff[i], out_size);
		printf("------------------------------\n");
	}

	close_icmp_socket(socket_id);
	
}
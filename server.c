#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	//printf("Server initialized...\n");
	while(1){
		printf("-----------------------------------------------\n");
		recieve_icmp_packet(socket_id, &packet);
		//printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		//printf("SRC:		%s\n", packet.src_addr);
		//printf("DEST:		%s\n", packet.dest_addr);
		//printf("TYPE:		%d\n", packet.type);
		//printf("FILETYPE:	%d\n", packet.file_type);
		//printf("ORDER:		%d\n", packet.order);
		//printf("FILENAME:	%s\n", packet.filename);

		//printf("Encrypt:\n");
	}
	close_icmp_socket(socket_id);
	
}
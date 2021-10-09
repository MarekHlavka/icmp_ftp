#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	printf("Server initialized...\n");
	while(1){
		recieve_icmp_packet(socket_id, &packet);
		printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		printf("SRC:		%s\n", packet.src_addr);
		printf("DEST:		%s\n", packet.dest_addr);
		printf("TYPE:		%d\n", packet.type);
		printf("FILETYPE:	%d\n", packet.file_type);
		printf("ORDER:		%d\n", packet.order);
		printf("FILENAME:	%s\n", packet.filename);
		printf("PLD_SIZE:   %d\n", strlen(packet.payload));

		char decrypted_buff[packet.decrypted_size];
		int decrypted_size = aes_encryption((unsigned char *)packet.payload,
			(unsigned  char *)decrypted_buff,
			AES_DECRYPT, packet.cipher_len,
			(unsigned char *)packet.iv);

		printf("Payload:\n%s\n", packet.payload);
		printf("_________________________________________\n");
	}
	close_icmp_socket(socket_id);
	
}
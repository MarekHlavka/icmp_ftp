#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	int test = 1;

	//printf("Server initialized...\n");
	while(test == 1){
		recieve_icmp_packet(socket_id, &packet);
		//printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
		//printf("SRC:		%s\n", packet.src_addr);
		//printf("DEST:		%s\n", packet.dest_addr);
		//printf("TYPE:		%d\n", packet.type);
		//printf("FILETYPE:	%d\n", packet.file_type);
		//printf("ORDER:		%d\n", packet.order);
		//printf("FILENAME:	%s\n", packet.filename);

		printf("%d\n", packet.cipher_len);
		printf("%d\n", packet.decrypted_size);
		printf("%s\n", packet.iv);

		printf("%s\n", packet.payload);

		//printf("Encrypt:\n");
		
		unsigned char decrypted_buff[packet.decrypted_size];
		int decrypted_size = aes_encryption((unsigned char *)packet.payload,
			decrypted_buff, AES_DECRYPT, packet.cipher_len, packet.iv);
		printf("_________________________________________\n");
		test = 0;
	}
	close_icmp_socket(socket_id);
	
}
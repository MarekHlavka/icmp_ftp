#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;
	int payload_size = 0;
	unsigned char *dec_payload;

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
		printf("Payload:\n%s\n", packet.payload);

		dec_payload = aes_encryption(packet.payload, AES_DECRYPT, &payload_size, packet.cipher_len);
		char enc_payload[payload_size + 1];
		memcpy(enc_payload, dec_payload, payload_size);
		free(dec_payload);

		enc_payload[payload_size + 1] = '\0';
		
		
		printf("_________________________________________\n");
	}
	close_icmp_socket(socket_id);
	
}
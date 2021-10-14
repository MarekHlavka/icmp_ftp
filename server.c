#include "server.h"

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	unsigned char **buff = NULL;
	int packet_count = 0;
	int last_size = 0;
	int cipher_len = 0;
	unsigned char iv[IV_SIZE];

	//printf("Server initialized...\n");
	while(1){
		recieve_icmp_packet(socket_id, &packet);

		cipher_len = packet.cipher_len;
		memcpy(iv, packet.iv, IV_SIZE);

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

		if(packet.count == packet_count){
			break;
		}
	}

	unsigned char *merged_buff = NULL;
	merged_buff = merge_payload(buff, packet_count, last_size);
	unsigned char decrypted[cipher_len*2];

	int decrypted_len = aes_encryption(merged_buff, decrypted, AES_DECRYPT, cipher_len, iv);

	decrypted[strlen((char *)decrypted)] = '\0';

	printf("%s\n", (char *)decrypted);

	close_icmp_socket(socket_id);
	
}
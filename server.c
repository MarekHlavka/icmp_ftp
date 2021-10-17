#include "server.h"

void send_file_response(int sock_id, char *src, char *dst, int order, int count){

	struct icmp_packet packet;

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);	
	set_reply_type(&packet);

	packet.file_type = OK_REPLY;
	packet.order = order;
	packet.count = count;
	packet.cipher_len = 0;
	packet.part_size = 0;
	packet.src_len = 0;
	packet.payload = NULL;
	// memset
	packet.iv = NULL;
	packet.filename = NULL;

	send_icmp_packet(sock_id, &packet);

}

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket();
	bind_icmp_socket(socket_id);

	unsigned char **buff = NULL;
	int packet_count = 0;
	int last_size = 0;
	int cipher_len = 0;
	int original_size = 0;
	unsigned char iv[IV_SIZE];
	char filename[MAX_FILENAME];
	char clinet_addr[100];
	char server_addr[100];

	//printf("Server initialized...\n");
	while(1){

		recieve_icmp_packet(socket_id, &packet);

		if(buff == NULL){
			buff = (unsigned char **)malloc(packet.count * MAX_PYLD_SIZE * sizeof(unsigned char));
			if(buff == NULL){
				perror("No memory available 1\n");
				close_icmp_socket(socket_id);
				exit(-1);
			}
			cipher_len = packet.cipher_len;
			original_size = packet.src_len;
			memcpy(iv, packet.iv, IV_SIZE);
			memcpy(filename, packet.filename, MAX_FILENAME);
			memcpy(clinet_addr, packet.src_addr, strlen(packet.src_addr));
			memcpy(server_addr, packet.dest_addr, strlen(packet.dest_addr));
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

	unsigned char *merged_buff = marge_payload(buff, packet_count, last_size);
	unsigned char *decrypted = (unsigned char *)malloc(original_size * sizeof(unsigned char));
	if(decrypted == NULL){
		perror("No memory available 1\n");
		close_icmp_socket(socket_id);
		exit(-1);
	}

	int decrypted_len = aes_encryption(merged_buff, decrypted, AES_DECRYPT, cipher_len, iv);

	//decrypted[strlen((char *)decrypted)] = '\0';

	write_file_as_byte_array(filename, decrypted, decrypted_len);

	//send_file_response();

	printf("CLINET: %s\nSERVER: %s\n", clinet_addr, server_addr);

	free(decrypted);
	free(merged_buff);

	close_icmp_socket(socket_id);
	
}
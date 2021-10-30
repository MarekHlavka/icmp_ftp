#include "server.h"

#define VER 6

void send_file_response(int sock_id, char *src, char *dst, int order,
	int count, int seq, int version){

	struct icmp_packet packet;

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);	
	set_reply_type(&packet, version);

	packet.file_type = OK_REPLY;
	packet.order = order;
	packet.count = count;
	packet.cipher_len = 0;
	packet.part_size = 0;
	packet.src_len = 0;
	packet.seq = seq;
	packet.payload = (unsigned char *)malloc(10 * sizeof(unsigned char *));
	packet.payload_size = 10;
	memcpy(packet.payload, "OK", 2);
	// memset
	memset(packet.iv, 0, IV_SIZE);
	memset(packet.filename, 0, MAX_FILENAME);

	printf("Sending filetype: %d\n", packet.file_type);
	send_icmp_packet(sock_id, &packet, version);
	free(packet.payload);

}

void run_server(){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket(VER, 1);
	bind_icmp_socket(socket_id, VER);

	// DOUBLE VARS FOR BOTH THREADS

	unsigned char **buff = NULL;
	int packet_count = 0;
	int last_size = 0;
	int cipher_len = 0;
	int original_size = 0;
	unsigned char iv[IV_SIZE];
	char filename[MAX_FILENAME];

	// Server for IPv4 -----------------------------------------------------------------
	while(1){

		printf("Listening......\n");
		// Listening for first packet of FTP ------------------------
		do{
			recieve_icmp_packet(socket_id, &packet, VER);
			printf("Recieved... %d\n", packet.file_type);
		}while(packet.file_type != FILE_MV);

		printf("Recieved valid packet\n");

		if(buff == NULL){
			buff = (unsigned char **)malloc(packet.count * MAX_PYLD_SIZE * sizeof(unsigned char));
			if(buff == NULL){
				perror("No memory available 1\n");
				close_icmp_socket(socket_id);
				exit(-1);
			}
		}

		cipher_len = packet.cipher_len;
		original_size = packet.src_len;
		memcpy(iv, packet.iv, IV_SIZE);
		memcpy(filename, packet.filename, MAX_FILENAME);

		// Cycling through rest of the packet of this
		while(1){

			printf("Order: %d\n", packet.order);

			buff[packet.order] = (unsigned char *)malloc(packet.part_size * sizeof(unsigned char));
			if(buff[packet.order] == NULL){
					perror("No memory available \n");
					close_icmp_socket(socket_id);
					exit(-1);
			}

			memcpy(buff[packet.order], packet.payload, packet.part_size);
			packet_count++;
			if(packet.order == packet_count -1){
				last_size = packet.part_size;
			}

			printf("Sending packet seq: %d\n", packet.seq);
			send_file_response(socket_id, packet.dest_addr, packet.src_addr,
				packet.order, packet.count, packet.seq, VER);

			if(packet.count == packet_count){
				break;
			}

			// MEMORY PROBLEMS ------------------------------------------------
			do{
				recieve_icmp_packet(socket_id, &packet, VER);
				printf("Recieved... %d\n", packet.file_type);
			}while(packet.file_type != FILE_MV && packet.type == (VER == 4? ICMP_ECHOREPLY:ICMP6_ECHO_REPLY));

		}

		printf("%d\n", original_size);

		DEBUG

		unsigned char *merged_buff = marge_payload(buff, packet_count, last_size);

		DEBUG

		unsigned char *decrypted = (unsigned char *)malloc(original_size * sizeof(unsigned char) * 4);
		unsigned char *original = (unsigned char *)malloc(original_size * sizeof(unsigned char));
		
		DEBUG

		if(decrypted == NULL){
			perror("No memory available 1\n");
			close_icmp_socket(socket_id);
			exit(-1);
		}

		DEBUG

		int decrypted_len = aes_encryption(merged_buff, decrypted, AES_DECRYPT, cipher_len, iv);
		memcpy(original, decrypted, original_size);

		printf("%d\n", decrypted_len);

		write_file_as_byte_array(filename, original, original_size);

		free_file_buff(buff, packet_count);
		free(original);
		free(decrypted);
		free(merged_buff);

		printf("File: %s saved...\n", filename);
	}

	close_icmp_socket(socket_id);
	
}
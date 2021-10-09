#include "packet_handle.h"
#include "aes.h"
#include "icmp_packet.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define KEY 		"xhlavk09"
#define KEY_SIZE 	32
#define IV_SIZE		KEY_SIZE/2

char** divide_payload(char* payload, int payload_size,
	int max_payload_size, int *count){

	int packet_count = payload_size / max_payload_size;

	if(payload_size % max_payload_size > 0){
		packet_count++;
	}

	*count = packet_count;

	printf("Payload size: %d\n", payload_size);
	printf("Max payload size: %d\n", max_payload_size);
	printf("Payload count size: %d\n", packet_count);

	char** payload_list = (char**)malloc(packet_count * sizeof(char*));
	if(payload_list == NULL){
		perror("No available memory\n");
		exit(EXIT_FAILURE);
	}

	for(int i = 0; i < packet_count; i++){

		payload_list[i] = (char *)malloc(max_payload_size * sizeof(char));
		if(payload_list[i] == NULL){
			perror("No available memory\n");
			exit(EXIT_FAILURE);
		}
		strncpy(payload_list[i], payload + (i * max_payload_size), max_payload_size);

	}

	return payload_list;

}

void free_file_buff(char **buff, int buff_cnt){

	for(int i = 0; i < buff_cnt; i++){
		free(buff[i]);
	}
	free(buff);

}

void random_char_array_gen(unsigned char *buff, int size){
	for(int i = 0; i < size; i++){
		buff[i] = (rand()%26)+65;
	}
}

unsigned char* aes_encryption(char* src_char, int mode, int *out_size, int cipher_len){

	// Copy source text
	int source_size = strlen(src_char);
	unsigned char *original = (unsigned char*)malloc(source_size*sizeof(unsigned char));
	memcpy(original, src_char, source_size);
	
	//printf("Original: %s\n", original);

	// Creating key
	unsigned char key[KEY_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, KEY, sizeof(KEY));

	// Creating IV
	unsigned char iv[IV_SIZE];
	random_char_array_gen(iv, IV_SIZE);

	if(mode == AES_ENCRYPT){
		unsigned char *ciphertext = (unsigned char*)malloc(source_size*8*sizeof(unsigned char));
		*out_size = encrypt(original, source_size, key, iv, ciphertext);
		free(original);
		//printf("Encrypted: %s\n", ciphertext);
		return ciphertext;
	}
	if(mode == AES_DECRYPT){
		unsigned char *decryptedtext = (unsigned char*)malloc(source_size*8*sizeof(unsigned char));
		*out_size = decrypt(original, cipher_len, key, iv, decryptedtext);
		free(original);
		//printf("Decrypted: %s\n", decryptedtext);
		return decryptedtext;
	}
	exit(EXIT_FAILURE);
}

void send_icmp_file(char *src, char *dst, char *payload, char *filename){

	char **buff;
	int packet_count = 1;
	int sock_id;
	int encrypt_size = 0;
	int payload_size = strlen(payload);
	unsigned char *encrypted_buff;
	struct icmp_packet packet;

	

	buff = divide_payload(payload, payload_size, MAX_PYLD_SIZE, &packet_count);
	
	sock_id = open_icmp_socket();

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);

	set_echo_type(&packet);
	packet.file_type = 1;
	strcpy(packet.filename, filename);


	for(int i = 0; i < packet_count; i++){	

		// Encrypt payload
		encrypted_buff = aes_encryption(buff[i], AES_ENCRYPT, &encrypt_size, 0);
		char tmp_buff[encrypt_size];
		memcpy(tmp_buff, encrypted_buff, encrypt_size);
		free(encrypted_buff);

		strcpy(packet.payload, tmp_buff);
		packet.cipher_len = encrypt_size;
		packet.payload_size = strlen(packet.payload);
		packet.order = i;


		send_icmp_packet(sock_id, &packet);

	}
	free_file_buff(buff, packet_count);
	close_icmp_socket(sock_id);




}
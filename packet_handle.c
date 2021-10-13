#include "packet_handle.h"
#include "aes.h"
#include "icmp_packet.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned char** divide_payload(unsigned char* payload, int payload_size,
 int *count, int *last_size){

	int packet_count = payload_size / MAX_PYLD_SIZE;
	*last_size = payload_size % MAX_PYLD_SIZE;

	if(*last_size > 0){
		packet_count++;
	}
	else{
		*last_size = MAX_PYLD_SIZE;
	}
	*count = packet_count;
	printf("%d\n%d\n", packet_count, payload_size);

	unsigned char** payload_list = (unsigned char**)malloc(packet_count * sizeof(unsigned char*));
	if(payload_list == NULL){
		perror("No available memory\n");
		exit(EXIT_FAILURE);
	}

	for(int i = 0; i < packet_count ; i++){

		payload_list[i] = (unsigned char *)malloc(MAX_PYLD_SIZE * sizeof(unsigned char));
		if(payload_list[i] == NULL){
			perror("No available memory\n");
			exit(EXIT_FAILURE);
		}
		memcpy(payload_list[i], payload + (i * MAX_PYLD_SIZE), MAX_PYLD_SIZE);

	}

	return payload_list;

}

void free_file_buff(unsigned char **buff, int buff_cnt){

	for(int i = 0; i < buff_cnt; i++){
		free(buff[i]);
	}
	free(buff);

}

void random_char_array_gen(unsigned char *buff, int size){
	for(int i = 0; i < size/2; i++){
		buff[i] = (rand()%26)+65;
	}
}

void create_file(char *name, char *content){
	FILE *file = fopen(name, "w");

	int result = fputs(content, file);
	if(result == EOF){
		perror("File write");
		exit(EXIT_FAILURE);
	}
	fclose(file);
}

int aes_encryption(unsigned char* src_char, unsigned char *dst_char,
	int mode, int src_len, unsigned char *iv_in){

	// Creating key
	unsigned char key[KEY_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, KEY, sizeof(KEY));

	// Creating IV
	unsigned char iv[IV_SIZE];
	memcpy(iv, iv_in, IV_SIZE);

	int decryptedtext_len, ciphertext_len;
	if(mode == AES_ENCRYPT){
		//Encrypt
		unsigned char ciphertext[src_len*3];
		ciphertext_len = encrypt(src_char, src_len, key, iv, ciphertext);
		memcpy(dst_char, ciphertext, ciphertext_len);

		BIO_dump_fp (stdout, (const char *)dst_char, ciphertext_len);

		return ciphertext_len;
	}
	if(mode == AES_DECRYPT){
		//Decrypt
		unsigned char decryptedtext[src_len*3];
		decryptedtext_len = decrypt(src_char, src_len, key, iv, decryptedtext);
		memcpy(dst_char, decryptedtext, decryptedtext_len);
		return decryptedtext_len;

	}
	return 0;
}

void send_icmp_file(char *src, char *dst, char *payload, char *filename){

	unsigned char **buff;
	int packet_count = 1;
	int sock_id;
	int payload_size = strlen(payload);
	int last_size;
	unsigned char unsigned_payload[payload_size];
	unsigned char iv[IV_SIZE];
	struct icmp_packet packet;

	memcpy(unsigned_payload, payload, payload_size);
	// Generate IV
	random_char_array_gen(iv, IV_SIZE);
	//printf("Original:\n%s\n", unsigned_payload);

	// Encrypt payload
	unsigned char encrypted_buff[payload_size*3];
	int encrypt_size = aes_encryption(unsigned_payload, encrypted_buff, AES_ENCRYPT, payload_size, iv);

	buff = divide_payload(encrypted_buff, encrypt_size, &packet_count, &last_size);
	
	sock_id = open_icmp_socket();

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);

	set_echo_type(&packet);
	packet.file_type = 1;
	packet.cipher_len = encrypt_size;
	packet.decrypted_size = payload_size;
	memcpy(packet.iv, iv, IV_SIZE);
	strcpy(packet.filename, filename);
	//printf("-------------------------------------------------------\n");
	//printf("Encrypted:\n%s\n", encrypted_buff);

	for(int i = 0; i < packet_count; i++){	

		int packet_size;
		if(i == packet_count - 1){
			packet_size = last_size;
		}
		else{
			packet_size = MAX_PYLD_SIZE;
		}

		packet.payload = (unsigned char *)malloc(packet_size*sizeof(unsigned char));

		DEBUG

		memcpy(packet.payload, buff[i], packet_size);
		packet.payload_size = packet_size;
		packet.part_size = packet_size;
		packet.order = i;

		send_icmp_packet(sock_id, &packet);

	}
	free_file_buff(buff, packet_count);
	close_icmp_socket(sock_id);




}
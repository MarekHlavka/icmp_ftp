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

unsigned char* merge_payload(unsigned char **source, int count, int last_size){

	int source_size = MAX_PYLD_SIZE;

	unsigned char *buff = (unsigned char *)malloc(((MAX_PYLD_SIZE * (count - 1) + last_size)) * sizeof(unsigned char));

	for(int i = 0; i < count ; i++){

		if(i == (count -1)){
			source_size = last_size;
		}
		memcpy(buff + (i * MAX_PYLD_SIZE), source[i], source_size);
		//free(source[i]);
	}

	//free(source);

	return buff;

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
		// TODO malloc --------------------------------------------------------------	
		unsigned char ciphertext[src_len*3];
		ciphertext_len = encrypt(src_char, src_len, key, iv, ciphertext);
		memcpy(dst_char, ciphertext, ciphertext_len);
		return ciphertext_len;
	}
	if(mode == AES_DECRYPT){
		//Decrypt
		// TODO malloc --------------------------------------------------------------
		unsigned char decryptedtext[src_len*3];
		decryptedtext_len = decrypt(src_char, src_len, key, iv, decryptedtext);
		memcpy(dst_char, decryptedtext, decryptedtext_len);
		return decryptedtext_len;

	}
	return 0;
}

void send_icmp_file(char *src, char *dst, char *payload,
	char *filename, int payload_size){

	unsigned char **buff;
	int packet_count = 1;
	int sock_id;
	int last_size;
	unsigned char unsigned_payload[payload_size];
	unsigned char iv[IV_SIZE];	
	struct icmp_packet packet;

	printf("%d\n", payload_size);

	memcpy(unsigned_payload, payload, payload_size);
	// Generate IV
	random_char_array_gen(iv, IV_SIZE);

	// Encrypt payload
	// TODO malloc --------------------------------------------------------------
	unsigned char encrypted_buff[payload_size*8];
	int encrypt_size = aes_encryption(unsigned_payload, encrypted_buff, AES_ENCRYPT, payload_size, iv);

	buff = divide_payload(encrypted_buff, encrypt_size, &packet_count, &last_size);

	sock_id = open_icmp_socket();

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);

	set_echo_type(&packet);
	packet.file_type = 1;
	packet.cipher_len = encrypt_size;
	packet.count = packet_count;
	memcpy(packet.iv, iv, IV_SIZE);
	strcpy(packet.filename, filename);

	for(int i = 0; i < packet_count; i++){	

		int packet_size;
		if(i == packet_count - 1){
			packet_size = last_size;
		}
		else{
			packet_size = MAX_PYLD_SIZE;
		}

		packet.payload = (unsigned char *)malloc(packet_size*sizeof(unsigned char));
		memcpy(packet.payload, buff[i], packet_size);
		packet.payload_size = packet_size;
		packet.part_size = packet_size;
		packet.order = i;

		send_icmp_packet(sock_id, &packet);

	}
	free_file_buff(buff, packet_count);
	close_icmp_socket(sock_id);




}
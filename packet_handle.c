#include "packet_handle.h"
#include "aes.h"
#include "icmp_packet.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

unsigned char* marge_payload(unsigned char **source, int count, int last_size){

	int source_size = MAX_PYLD_SIZE;

	unsigned char *buff = (unsigned char *)malloc(((MAX_PYLD_SIZE * (count - 1) + last_size)) * sizeof(unsigned char));

	for(int i = 0; i < count ; i++){

		if(i == (count -1)){
			source_size = last_size;
		}
		memcpy(buff + (i * MAX_PYLD_SIZE), source[i], source_size);
		free(source[i]);
	}

	free(source);

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
		unsigned char *ciphertext = (unsigned char *)malloc(src_len * sizeof(unsigned char) * 4);
		if(ciphertext == NULL){
			perror("No memory available 1\n");
			exit(-1);
		}
		ciphertext_len = encrypt(src_char, src_len, key, iv, ciphertext);
		memcpy(dst_char, ciphertext, ciphertext_len);
		free(ciphertext);
		return ciphertext_len;
	}
	if(mode == AES_DECRYPT){
		//Decrypt
		unsigned char *decryptedtext = (unsigned char *)malloc(src_len * sizeof(unsigned char) * 2);
		if(decryptedtext == NULL){
			perror("No memory available 1\n");
			exit(-1);
		}
		decryptedtext_len = decrypt(src_char, src_len, key, iv, decryptedtext);
		memcpy(dst_char, decryptedtext, decryptedtext_len);
		free(decryptedtext);
		return decryptedtext_len;

	}
	return 0;
}

void send_icmp_file(char *src, char *dst, char *payload,
	char *filename, int payload_size, int version){

	unsigned char **buff;
	int packet_count = 1;
	int sock_id;
	int last_size;
	unsigned char unsigned_payload[payload_size];
	unsigned char iv[IV_SIZE];	
	struct icmp_packet packet;
	struct icmp_packet rcvr_packet;

	printf("%d\n", payload_size);

	memcpy(unsigned_payload, payload, payload_size);
	// Generate IV
	random_char_array_gen(iv, IV_SIZE);

	// Encrypt payload
	unsigned char *encrypted_buff = (unsigned char *)malloc(payload_size*sizeof(unsigned char)*4);
	if(encrypted_buff == NULL){
		perror("No memory available 1\n");
		exit(-1);
	}
	int encrypt_size = aes_encryption(unsigned_payload, encrypted_buff, AES_ENCRYPT, payload_size, iv);

	buff = divide_payload(encrypted_buff, encrypt_size, &packet_count, &last_size);

	sock_id = open_icmp_socket(version);

	memcpy(packet.src_addr, src, strlen(src) + 1);
	memcpy(packet.dest_addr, dst, strlen(dst) + 1);

	set_echo_type(&packet);
	packet.file_type = FILE_MV;
	packet.cipher_len = encrypt_size;
	packet.count = packet_count;
	packet.src_len = payload_size;
	packet.seq = 0;
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

		printf("Sending packet %d\n", packet.seq);
		send_icmp_packet(sock_id, &packet, version);

		do{
			recieve_icmp_packet(sock_id, &rcvr_packet);
		}while(rcvr_packet.file_type != OK_REPLY && packet.seq == rcvr_packet.seq);

		packet.seq++;
		// sleep(1);

		free(packet.payload);

	}
	free(encrypted_buff);
	free_file_buff(buff, packet_count);
	close_icmp_socket(sock_id);




}
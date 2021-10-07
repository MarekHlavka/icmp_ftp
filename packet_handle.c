#include "packet_handle.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

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

void random_char_array_gen(unsigned char *buff, int size){
	for(int i = 0; i < size; i++){
		buff[i] = (rand()%26)+65;
	}
}

char* aes_encryption(char* src_char){

	// Copy source text
	int source_size = strlen(src_char);
	unsigned char *original = (unsigned char*)malloc(source_size*sizeof(unsigned char));
	memcpy(original, src_char, source_size);
	
	printf("Original: %s\n", original);

	// Creating key
	unsigned char key[KEY_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, KEY, sizeof(KEY));

	// Creating IV
	unsigned char iv[IV_SIZE];
	random_char_array_gen(iv, IV_SIZE);

	// Creating buffers
	unsigned char ciphertext[source_size*8];
	unsigned char decryptedtext[source_size*8];

	int decryptedtext_len, ciphertext_len;

	//Encrypt
	ciphertext_len = encrypt(original, source_size, key, iv, ciphertext);

	printf("Encrypted: %s\n", ciphertext);

	//Decrypt
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

	decryptedtext[decryptedtext_len] = '\0';

	printf("Decrypted: %s\n", decryptedtext);

	free(original);

	return src_char;
}
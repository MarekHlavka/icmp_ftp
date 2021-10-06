#include "packet_handle.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

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

char* aes_encryption(char* src_char){

	int keylength = 256;
	char key[100] = "xhlavk09";
	unsigned char aes_key[keylength/8];
	memset(aes_key, 0, sizeof(aes_key));
	memcpy(aes_key, key, sizeof(key));
	size_t inputs_length = strlen(src_char);

	printf("Original: %s\n", src_char);

	unsigned char iv[AES_BLOCK_SIZE];
	RAND_bytes(iv, AES_BLOCK_SIZE);

	const size_t encslength = (inputs_length + AES_BLOCK_SIZE);
	unsigned char enc_out[encslength];
	unsigned char dec_out[inputs_length];
	memset(enc_out, 0, sizeof(enc_out));
	memset(dec_out, 0, sizeof(dec_out));

	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_cbc_encrypt((unsigned char*)src_char, enc_out, inputs_length, &enc_key, iv, AES_ENCRYPT);

	AES_set_decrypt_key(aes_key, keylength, &dec_key);
	AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv, AES_DECRYPT);

	printf("Original: %s\n", src_char);
	printf("Decrypted: %s\n", enc_out);
	printf("Encrypted: %s\n", dec_out);


	return src_char;
}
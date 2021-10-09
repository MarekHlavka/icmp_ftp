#ifndef PACKET_HANDLE
#define PACKET_HANDLE

#include "icmp_packet.h"

#define DEBUG printf("Hello %d\n", __LINE__);	
#define AES_ENCRYPT 	0
#define AES_DECRYPT		1

char** divide_payload(char* payload, int payload_size,
	int max_payload_size, int *count);

void free_file_buff(char **buff, int buff_cnt);

void random_char_array_gen(unsigned char *buff, int size);

unsigned char* aes_encryption(char* src_char, int mode, int *out_size, int cipher_len);

void send_icmp_file(char *src, char *dst, char *payload, char *filename);
#endif //PACKET_HANDLE
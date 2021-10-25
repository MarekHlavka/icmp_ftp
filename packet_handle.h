#ifndef PACKET_HANDLE
#define PACKET_HANDLE

#include "icmp_packet.h"

#define DEBUG printf("Hello %d\n", __LINE__);	

unsigned char** divide_payload(unsigned char* payload, int payload_size,
	int *count, int *last_size);

unsigned char* marge_payload(unsigned char **source, int count, int last_size);

void random_char_array_gen(unsigned char *buff, int size);

int aes_encryption(unsigned char* src_char, unsigned char *dst_char,
	int mode, int src_len, unsigned char *iv_in);

void send_icmp_file(char *src, char *dst, char *payload,
	char *filename, int payload_size, int version);

#endif //PACKET_HANDLE
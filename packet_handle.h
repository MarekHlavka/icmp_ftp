#ifndef PACKET_HANDLE
#define PACKET_HANDLE

#include "icmp_packet.h"

#define DEBUG printf("Hello %d\n", __LINE__);	

char** divide_payload(char* payload, int payload_size,
	int max_payload_size, int *count);

void random_char_array_gen(unsigned char *buff, int size);

char* aes_encryption(char* src_char);

void send_icmp_file();
#endif //PACKET_HANDLE
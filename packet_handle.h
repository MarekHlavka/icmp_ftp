#ifndef PACKET_HANDLE
#define PACKET_HANDLE

char** divide_payload(char* payload, int payload_size,
	int max_payload_size, int *count);

char* aes_encryption(char* src_char);
#endif //PACKET_HANDLE
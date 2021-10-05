#ifndef PACKET_HANDLE
#define PACKET_HANDLE

char** divide_payload(char* payload, int payload_size,
	int max_payload_size, int *count);

#endif //PACKET_HANDLE
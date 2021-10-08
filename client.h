#ifndef CLIENT
#define CLIENT

#include "icmp_packet.h"
#include "file_handle.h"
#include "packet_handle.h"

#include <string.h>
#include <stdio.h>

void run_client(char *server_address, char *src_filename);

#endif //CLIENT
#ifndef SERVER
#define SERVER

#include "icmp_packet.h"
#include "file_handle.h"
#include "packet_handle.h"
#include "aes.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

void run_server();

#endif //SERVER
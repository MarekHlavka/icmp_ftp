//
// Created by marek on 30.09.2021.
//

#include "icmp_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define CLIENT_MODE 0
#define SERVER_MODE 1

#define DEF_IP 0.0.0.0

/*
int main(int argc, char *argv[]) {

    return 0;
}
*/


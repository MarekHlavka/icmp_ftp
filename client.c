#include "client.h"
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_ADDR_LEN	256

int address_lookup(char *dst){
	char buf[128];
    if (inet_pton(AF_INET, dst, buf)) {
        return 4;
    } else if (inet_pton(AF_INET6, dst, buf)) {
        return 6;
    }
    return -1;

}

void run_client(char *address, char *src_filename){

	char *payload;
	char src_ip[MAX_ADDR_LEN];
	char dst_ip[MAX_ADDR_LEN];
	int payload_len;

	int ip_version = address_lookup(address);
	if(ip_version == -1){
		perror("Wrong address format");
		exit(-1);
	}
	if(ip_version == 4){

		struct hostent *dst_hstmn;
		struct hostent *src_hstmn;

		dst_hstmn = gethostbyname(address);
		if(dst_hstmn == NULL){
			perror("Unknown hostname");
			exit(-1);
		}
		strcpy(dst_ip, inet_ntoa(*((struct in_addr*)dst_hstmn->h_addr_list[0])));
		src_hstmn = gethostbyname("0.0.0.0");
		strcpy(src_ip, inet_ntoa(*((struct in_addr*)src_hstmn->h_addr_list[0])));
	}
	else{

		struct addrinfo *res = NULL;
		getaddrinfo(address, NULL, NULL, &res);
	}
	

	payload = read_file_as_byte_array(src_filename, &payload_len);

	//send_icmp_file(src_ip, dst_ip, payload, src_filename, payload_len);

}
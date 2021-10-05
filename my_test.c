#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "icmp.h"

#define S_PORT  6398
#define MAX_BUF 1024

int main(int argc, char **argv){
	// Client
	if(argc >= 2){
		int sock_id, opt = 1;

		struct sockaddr_in servaddr;
		char buf[MAX_BUF];
		int status;

		// ############### create a socket ########
		sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(sock_id == -1){
			perror("Unable to open ICMP socket\n");
			exit(EXIT_FAILURE);
		}
		if(setsockopt(sock_id, IPPROTO_IP, IP_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
			perror("Unable to set IP_HDRINCL socket option\n");
			exit(EXIT_FAILURE);
		}

		// ############### setting server address ##########
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.sin_port = htons(S_PORT);

		// ############### connection to server ##########
		status = connect(sock_id, (struct sockaddr)&servaddr, sizeof(servaddr));
		if(status == -1){
			perror("Cannot connect to server\n");
			exit(EXIT_FAILURE);
		}

	}
	// Server
	else{
		int opt = 1;
		int sock_id, sock_id_2;
		int addrlen;
		struct sockaddr_in client, peer;
		int status;

		// ############ create socket ###########
		sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(sock_id == -1){
			perror("Unable to open ICMP socket\n");
			exit(EXIT_FAILURE);
		}
		if(setsockopt(sock_id, IPPROTO_IP, IP_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
			perror("Unable to set IP_HDRINCL socket option\n");
			exit(EXIT_FAILURE);
		}

		client.sin_family = AF_INET;
		client.sin_addr.s_addr = INADDR_ANY;
		client.sin_port = htons(S_PORT);

		status = bind(sock_id, (struct sockaddr*)&client, sizeof(client));
		if (status == -1)
		{
			perror("Binding error\n");
			exit(1);
		}

		status = listen(sock_id, 5);
		if (status == -1){
			perror("Listening error\n");
			exit(1);
		}
	}
	
}
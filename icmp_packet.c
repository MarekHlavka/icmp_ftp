#include "icmp_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// Opening socket for ICMP
int open_icmp_socket(){

	int sock_id, opt = 1;

	sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if(sock_id == -1){
		perror("Unable to open ICMP socket\n");
		exit(EXIT_FAILURE);
	}

	if(setsockopt(sock_id, IPPROTO_IP, IP_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
		perror("Unable to set IP_HDRINCL socket option\n");
		exit(EXIT_FAILURE);
	}

	return sock_id;
}

// Binding ICMP socket
int bind_icmp_socket(int sock_id){

	struct sockaddr_in servaddr;

	memset(&servaddr, 0, sizeof(struct, sockaddr_inn));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDRANY);

	// binding socket
	if(bind(sock_id, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_inn)) == -1)
	{
		perror("Unable to bind\n");
		exit(EXIT_FAILURE);

	}

}

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp){
	ip->version = 4;	
	ip->ihl = 5;
	ip->tos = 0;
	ip->id = rand();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_ICMP;

	icmp->code = 0;
	icmp->un.echo.sequence = rand();
	icmp->un.echo.id = rand();
	icmp->checksum = 0;
}
#include "icmp_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG printf("Hello %d\n", __LINE__);

uint16_t in_cksum(uint16_t *addr, int len);

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp);

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
void bind_icmp_socket(int sock_id){

	struct sockaddr_in servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// binding socket
	if(bind(sock_id, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)) == -1)
	{
		perror("Unable to bind\n");
		exit(EXIT_FAILURE);

	}

}

void send_icmp_packet(int sock_id, struct icmp_packet *packet_details)
{

	// Source ane destination IP addresses
	struct in_addr src_addr;
	struct in_addr dest_addr;

	struct iphdr *ip;
	struct icmphdr *icmp;
	struct s_icmp_file_info *icmp_file;
	char *icmp_payload;

	int packet_size;
	char *packet;

	struct sockaddr_in servaddr;

	inet_pton(AF_INET, packet_details->src_addr, &src_addr);
	inet_pton(AF_INET, packet_details->dest_addr, &dest_addr);

	packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size;
	packet = calloc(packet_size, sizeof(uint8_t));
	if(packet == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(EXIT_FAILURE);
	}

	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
	icmp_file = (struct s_icmp_file_info*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr)); 
	icmp_payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

	prepare_hdr(ip, icmp);

	

	ip->tot_len = htons(packet_size);
	ip->saddr = src_addr.s_addr;
	ip->daddr = dest_addr.s_addr;

	memcpy(icmp_payload, packet_details->payload, packet_details->payload_size);
	

	icmp->type = packet_details->type;
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + packet_details->payload_size);
	
	icmp_file->type = packet_details->file_type;
	icmp_file->order = packet_details->order;
	icmp_file->cipher_len = packet_details->cipher_len;
	memcpy(icmp_file->filename, packet_details->filename, MAX_FILENAME);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = dest_addr.s_addr;
	
	sendto(sock_id, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	
	free(packet);
}



void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details){

	struct sockaddr_in src_addr;
	//struct sockaddr_in dest_addr;

	struct iphdr *ip;
	struct icmphdr *icmp;
	struct s_icmp_file_info *icmp_file;
	char *icmp_payload;

	int packet_size;
	char *packet;

	socklen_t src_addr_size;

	packet = calloc(MAX_PYLD_SIZE, sizeof(uint8_t));
	if(packet == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}

	src_addr_size = sizeof(struct sockaddr_in);

	//Recieving packet
	packet_size = recvfrom(sock_id, packet, MAX_PYLD_SIZE, 0, (struct sockaddr *)&(src_addr), &src_addr_size);

	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
	icmp_file = (struct s_icmp_file_info *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
	icmp_payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

	// packet details
	inet_ntop(AF_INET, &(ip->saddr), packet_details->src_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->daddr), packet_details->dest_addr, INET_ADDRSTRLEN);
	packet_details->type = icmp->type;
	packet_details->payload_size = packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr) - sizeof(struct s_icmp_file_info);
	packet_details->payload = calloc(packet_details->payload_size, sizeof(uint8_t));
	if(packet_details->payload == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}
	memcpy(packet_details->payload, icmp_payload, packet_details->payload_size);

	packet_details->file_type = icmp_file->type;
	packet_details->order = icmp_file->order;
	memcpy(packet_details->filename, icmp_file->filename, MAX_FILENAME);

	free(packet);

}

void set_echo_type(struct icmp_packet *packet){
	packet->type = ICMP_ECHO;
}

void set_reply_type(struct icmp_packet *packet){
	packet->type = ICMP_ECHOREPLY;
}

void close_icmp_socket(int sock_id){
	close(sock_id);
}

uint16_t in_cksum(uint16_t *addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  // Adding 16 bits sequentially in sum
  while (nleft > 1) {
    sum += *w;
    nleft -= 2;
    w++;
  }

  // If an odd byte is left
  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
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
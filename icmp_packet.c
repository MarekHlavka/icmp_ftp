#include "icmp_packet.h"
#include "packet_handle.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define DEBUG printf("Hello %d\n", __LINE__);

uint16_t in_cksum(uint16_t *addr, int len);

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp);

/*
* Dunkce na otevření raw socketu a nastavení sokcetu
* aby bylo možné posílat ICMP pakety
*/
int open_icmp_socket()
{

	int sock_id, opt = 1;

	sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sock_id == -1){													// Kontrola otevření soketu
		perror("Unable to open ICMP socket\n");
		exit(EXIT_FAILURE);
	}

	// Nastavení soketu
	if(setsockopt(sock_id, IPPROTO_IP, IP_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
		perror("Unable to set IP_HDRINCL socket option\n");
		exit(EXIT_FAILURE);
	}

	return sock_id;
}

/*
* Funkce na nastevení poslouchání na soketu na danou adressu
* (INADDR_ANY = jakákoliv)
*/
void bind_icmp_socket(int sock_id)
{

	struct sockaddr_in servaddr;

	// Nastavení detailů pro přijímaní na socketu
	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Samotné nastavení socketu
	if(bind(sock_id, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)) == -1)
	{
		perror("Unable to bind\n");
		exit(EXIT_FAILURE);

	}
}

/*
* Funkce na poslání ICMP paketu
*/
void send_icmp_packet(int sock_id, struct icmp_packet *packet_details)
{

	struct in_addr src_addr;						// IP adresa zdroje
	struct in_addr dest_addr;						// IP adresa cíle
	struct iphdr *ip;										// struktura IP hlavičky
	struct icmphdr *icmp;								// struktura ICMP hlavičky
	struct s_icmp_file_info *icmp_file;	// struktura ICMP_file hlavičky
	unsigned char *icmp_payload;				// ukazatel na začítek přenášených dat

	int packet_size;		// Velikost pro alokování paměti pro paket
	char *packet;				// Ukazatel na místo alokované pro paket

	struct sockaddr_in servaddr;

	// Konverze IP adres
	inet_pton(AF_INET, packet_details->src_addr, &src_addr);
	inet_pton(AF_INET, packet_details->dest_addr, &dest_addr);

	// Výpočet velikosti paketu
	packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size;

	// Alokování paketu
	packet = calloc(packet_size, sizeof(uint8_t));
	if(packet == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(EXIT_FAILURE);
	}

	// Výpočet konkrétních míst v paměti pro jednotlivé hlavičky a náklad
	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
	icmp_file = (struct s_icmp_file_info*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr)); 
	icmp_payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

	// Vyplnění nepotřebbných položek IP a ICMP hlaviček
	prepare_hdr(ip, icmp);

	// Vyplnění IP hlavičky
	ip->tot_len = htons(packet_size);		// Délka
	ip->saddr = src_addr.s_addr;				// Zdrojová IP
	ip->daddr = dest_addr.s_addr;				// Cílová IP

	// Vyplnění ICMP hlavičky
	icmp->type = packet_details->type;	// typ echo-request/reply
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + packet_details->payload_size);
	
	// Vyplnění ICMP_file hlavičky
	icmp_file->type = packet_details->file_type;				// Typ paketu
	icmp_file->order = packet_details->order;						// Pořadí paketu
	icmp_file->cipher_len = packet_details->cipher_len;	// Délka celkové šifry
	icmp_file->count = packet_details->count;						// Počet posílaných paketů
	icmp_file->part_size = packet_details->part_size;		// Velikost nákladu aktuálnícho paketu

	// Kopírování nečíselných položek
	memcpy(icmp_payload, packet_details->payload, packet_details->part_size);
	memcpy(icmp_file->iv, packet_details->iv, IV_SIZE);
	memcpy(icmp_file->filename, packet_details->filename, MAX_FILENAME);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	
	// Nastevení detailů struktury pro uchovávání adresy
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = dest_addr.s_addr;	
	sendto(sock_id, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	
	free(packet);
}

/*
* Funkce na přijímání ICMP paketu
*/
void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details)
{

	struct sockaddr_in src_addr;
	//struct sockaddr_in dest_addr;

	struct iphdr *ip;											// IP hlavička
	struct icmphdr *icmp;									// ICMP hlavička
	struct s_icmp_file_info *icmp_file;		// ICMP_file hlavička
	unsigned char *icmp_payload;					// Ukazatel na náklad paketu

	int packet_size;
	char *packet;

	socklen_t src_addr_size;

	// Alokování paměti pro paket
	packet = calloc(MTU, sizeof(uint8_t));
	if(packet == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}

	src_addr_size = sizeof(struct sockaddr_in);

	// Přijímání paketu
	packet_size = recvfrom(sock_id, packet, MTU, 0, (struct sockaddr *)&(src_addr), &src_addr_size);

	// Výpočet konkrétních míst v paměti pro jednotlivé hlavičky a náklad
	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
	icmp_file = (struct s_icmp_file_info *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
	icmp_payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

	// Konverze IP adres
	inet_ntop(AF_INET, &(ip->saddr), packet_details->src_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->daddr), packet_details->dest_addr, INET_ADDRSTRLEN);

	// Ukládání položek z jednotlivých hlaviček do struktury
	// pro jednodušší přístup
	packet_details->type = icmp->type;
	packet_details->payload_size = packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr) - sizeof(struct s_icmp_file_info);
	packet_details->file_type = icmp_file->type;
	packet_details->order = icmp_file->order;
	packet_details->cipher_len = icmp_file->cipher_len;
	packet_details->count = icmp_file->count;
	packet_details->part_size = icmp_file->part_size;

	// Alokování místo pro zbytek dat, kromě hlaviček
	packet_details->payload = calloc(packet_details->part_size, sizeof(uint8_t));
	if(packet_details->payload == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}

	// Kopírování nečíselných položek
	memcpy(packet_details->payload, icmp_payload, packet_details->part_size);
	memcpy(packet_details->iv, icmp_file->iv, IV_SIZE);
	memcpy(packet_details->filename, icmp_file->filename, MAX_FILENAME);

	free(packet);
}

void set_echo_type(struct icmp_packet *packet){
	packet->type = ICMP_ECHO;
}

void set_reply_type(struct icmp_packet *packet){
	packet->type = ICMP_ECHOREPLY;
}

/*
* Funkce na zavření socketu
*/
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
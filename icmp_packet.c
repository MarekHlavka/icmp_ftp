#include "icmp_packet.h"
#include "packet_handle.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define DEBUG printf("Hello %d\n", __LINE__);

uint16_t in_cksum(uint16_t *addr, int len);

uint16_t in6_cksum(struct ip6_hdr *ip6, uint16_t *payload, int payload_size);

void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp, int seq);

void prepare_icmp(struct icmphdr *icmp, int seq);

/*
* Dunkce na otevření raw socketu a nastavení sokcetu
* aby bylo možné posílat ICMP pakety
*/
int open_icmp_socket(int version)
{

	int sock_id, opt = 1;
	if(version == 4){	// IPv4
		sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(sock_id == -1){													// Kontrola otevření soketu
			perror("Unable to open ICMP socket");
			exit(EXIT_FAILURE);
		}

		// Nastavení soketu
		if(setsockopt(sock_id, IPPROTO_IP, IP_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
			perror("Unable to set IP_HDRINCL socket option");
			exit(EXIT_FAILURE);
		}
	}
	else{
		sock_id = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if(sock_id == -1){
			perror("Unable to open ICMPv6 socket");
			exit(EXIT_FAILURE);
		}

		if(setsockopt(sock_id, IPPROTO_IPV6, IPV6_HDRINCL, (const char *)&opt, sizeof(opt)) == -1){
			perror("Unable to set IPV6_HDRINCL socket option");
			exit(EXIT_FAILURE);
		}
	}

	return sock_id;
}

/*
* Funkce na nastevení poslouchání na soketu na danou adressu
* (INADDR_ANY = jakákoliv)
*/
void bind_icmp_socket(int sock_id, int version)
{
	if(version == 4){

		struct sockaddr_in servaddr;
		// Nastavení detailů pro přijímaní na socketu
		memset(&servaddr, 0, sizeof(struct sockaddr_in));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

		// Samotné nastavení socketu
		if(bind(sock_id, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)) == -1)
		{
			perror("Unable to bind IPv4 socket");
			exit(EXIT_FAILURE);

		}
	}
	else{

		DEBUG

		struct sockaddr_in6 servaddr;
		memset(&servaddr, 0, sizeof(struct sockaddr_in6));
		servaddr.sin6_family = AF_INET6;
		servaddr.sin6_port = htons(0);

		if(bind(sock_id, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
		{
			perror("Unable to bind IPv6 socket");
			exit(EXIT_FAILURE);
		}
	}
}

/*
* Funkce na poslání ICMP paketu
*/
void send_icmp_packet(int sock_id, struct icmp_packet *packet_details, int version)
{

	struct iphdr *ip;							// struktura IP hlavičky
	struct ip6_hdr *ip6;
	struct icmphdr *icmp;						// struktura ICMP hlavičky
	struct s_icmp_file_info *icmp_file;			// struktura ICMP_file hlavičky
	unsigned char *icmp_payload;				// ukazatel na začítek přenášených dat
	int packet_size;							// Velikost pro alokování paměti pro paket
	char *packet;								// Ukazatel na místo alokované pro paket

	struct sockaddr_in servaddr;
	struct sockaddr_in6 servaddr6;

	printf("%s\n%s\n", packet_details->src_addr, packet_details->dest_addr);

	// Konverze IP adres
	if(version == 4){	// IPv4 ---------------------------------------------------------------------

		struct in_addr src_addr;					// IP adresa zdroje
		struct in_addr dest_addr;					// IP adresa cíle

		printf("%d\n", inet_pton(AF_INET, packet_details->src_addr, &src_addr));
		printf("%d\n", inet_pton(AF_INET, packet_details->dest_addr, &dest_addr));

		// Výpočet velikosti paketu
		packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size;

		// Alokování paketu
		packet = calloc(packet_size, sizeof(uint8_t));
		if(packet == NULL){
			perror("No memory available");
			close_icmp_socket(sock_id);
			exit(EXIT_FAILURE);
		}

		// Výpočet konkrétních míst v paměti pro jednotlivé hlavičky a náklad
		ip = (struct iphdr *)packet;
		icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
		icmp_file = (struct s_icmp_file_info*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr)); 
		icmp_payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

		// Vyplnění nepotřebbných položek IP a ICMP hlaviček
		prepare_hdr(ip, icmp, packet_details->seq);

		// Vyplnění IP hlavičky
		ip->tot_len = htons(packet_size);			// Délka
		ip->saddr = src_addr.s_addr;				// Zdrojová IP
		ip->daddr = dest_addr.s_addr;				// Cílová IP

		// Nastevení detailů struktury pro uchovávání adresy
		memset(&servaddr, 0, sizeof(struct sockaddr_in));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = dest_addr.s_addr;

	}
	else{		// IPv6 ------------------------------------------------------------------------------

		packet_size = sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size;

		packet = calloc(packet_size, sizeof(uint8_t));
		if(packet == NULL){
			perror("No memory available");
			close_icmp_socket(sock_id);
			exit(EXIT_FAILURE);
		}

		ip6 = (struct ip6_hdr *)packet;
		icmp = (struct icmphdr*)(packet + sizeof(struct ip6_hdr));
		icmp_file = (struct s_icmp_file_info*)(packet + sizeof(struct ip6_hdr) + sizeof(struct icmphdr)); 
		icmp_payload = (unsigned char *)(packet + sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));

		prepare_icmp(icmp, packet_details->seq);

		ip6->ip6_flow = packet_details->seq;
		ip6->ip6_hlim = 255;
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_plen = htons(packet_details->payload_size);

		printf("%d\n", inet_pton(AF_INET6, packet_details->src_addr, &(ip6->ip6_src)));
		printf("%d\n", inet_pton(AF_INET6, packet_details->dest_addr, &(ip6->ip6_dst)));

		memset(&servaddr6, 0, sizeof(struct sockaddr_in6));
		servaddr6.sin6_family = AF_INET6;
		servaddr6.sin6_addr = ip6->ip6_dst;

		ip6->ip6_vfc = 0x60;

	}
	// Až sem  bude diference mezi IP a IPv6 -------------------------------------

	// Vyplnění ICMP hlavičky
	icmp->type = packet_details->type;	// typ echo-request/reply
	icmp->checksum = 0;

	// Vyplnění ICMP_file hlavičky
	icmp_file->type = packet_details->file_type;				// Typ paketu
	icmp_file->order = packet_details->order;						// Pořadí paketu
	icmp_file->cipher_len = packet_details->cipher_len;	// Délka celkové šifry
	icmp_file->count = packet_details->count;						// Počet posílaných paketů
	icmp_file->part_size = packet_details->part_size;		// Velikost nákladu aktuálnícho paketu
	icmp_file->src_len = packet_details->src_len;				// Délka originálního souboru

	// Kopírování nečíselných položek
	memcpy(icmp_payload, packet_details->payload, packet_details->part_size);
	memcpy(icmp_file->iv, packet_details->iv, IV_SIZE);
	memcpy(icmp_file->filename, packet_details->filename, MAX_FILENAME);


	printf("PYLD size:%d\n", sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size);

	int retval = 0;
	if(version == 4){
		icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size);
		retval = sendto(sock_id, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	}
	else{
		icmp->checksum = in6_cksum(ip6, (unsigned short *)icmp, sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info) + packet_details->payload_size);
		retval = sendto(sock_id, packet, packet_size, 0, (struct sockaddr *)&servaddr6, sizeof(struct sockaddr_in6));

		DEBUG

	}
	printf("%d\n", retval);
	if(retval == -1){

		printf("Socket error %d\n", errno);
		exit(EXIT_FAILURE);

	}

	free(packet);
}

/*
* Funkce na přijímání ICMP paketu
*/
void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details, int version)
{

	// TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO 

	struct icmphdr *icmp;							// ICMP hlavička
	struct s_icmp_file_info *icmp_file;				// ICMP_file hlavička
	unsigned char *icmp_payload;					// Ukazatel na náklad paketu

	int packet_size;
	int header_size;
	char *packet;

	socklen_t src_addr_size;

	// Alokování paměti pro paket
	packet = calloc(MTU, sizeof(uint8_t));
	if(packet == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}

	// IPv4 -------------------------------------------------------------------------------
	if(version == 4){


		struct sockaddr_in src_addr;
		struct iphdr *ip;								// IP hlavička

		src_addr_size = sizeof(struct sockaddr_in);
		header_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info);

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

		if(ip->protocol != IPPROTO_ICMP){
			packet_details->file_type = 0;
			return;
		}

	}
	// IPv6 ---------------------------------------------------------------------------------
	else{

		struct sockaddr_in6 src_addr;
		struct ip6_hdr *ip6;

		src_addr_size = sizeof(struct sockaddr_in6);
		header_size = sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info);

		DEBUG
		packet_size = recvfrom(sock_id, packet, MTU, 0, (struct sockaddr *)&(src_addr), &src_addr_size);
		if(packet_size < 0){
			printf("Server error: %d\n", errno);
			perror("Reading packet");
			exit(EXIT_FAILURE);
		}

		DEBUG

		// Výpočet konkrétních míst v paměti pro jednotlivé hlavičky a náklad
		ip6 = (struct ip6_hdr *)packet;
		icmp = (struct icmphdr *)(packet + sizeof(struct ip6_hdr));
		icmp_file = (struct s_icmp_file_info *)(packet + sizeof(struct ip6_hdr) + sizeof(struct icmphdr));
		icmp_payload = (unsigned char *)(packet + sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(struct s_icmp_file_info));		

		// Konverze IP adres
		inet_ntop(AF_INET6, &(ip6->ip6_src), packet_details->src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6->ip6_dst), packet_details->dest_addr, INET6_ADDRSTRLEN);

		if(ip6->ip6_nxt != IPPROTO_ICMPV6){
			packet_details->file_type = 0;
			return;
		}
	}

	// Ukládání položek z jednotlivých hlaviček do struktury
	// pro jednodušší přístup
	packet_details->type = icmp->type;
	packet_details->seq = icmp->un.echo.sequence;
	packet_details->payload_size = packet_size - header_size;
	packet_details->file_type = icmp_file->type;
	packet_details->order = icmp_file->order;
	packet_details->cipher_len = icmp_file->cipher_len;
	packet_details->count = icmp_file->count;
	packet_details->part_size = icmp_file->part_size;
	packet_details->src_len = icmp_file->src_len;

	// Alokování místo pro zbytek dat, kromě hlaviček
	packet_details->payload = calloc(packet_details->part_size, sizeof(uint8_t));
	if(packet_details->payload == NULL){
		perror("No memory available\n");
		close_icmp_socket(sock_id);
		exit(-1);
	}

	DEBUG

	// Kopírování nečíselných položek
	memcpy(packet_details->payload, icmp_payload, packet_details->part_size);

	DEBUG

	memcpy(packet_details->iv, icmp_file->iv, IV_SIZE);

	DEBUG

	memcpy(packet_details->filename, icmp_file->filename, MAX_FILENAME);

	free(packet);
}

void set_echo_type(struct icmp_packet *packet, int version){
	packet->type = (version == 4)?ICMP_ECHO:ICMP6_ECHO_REQUEST;
}

void set_reply_type(struct icmp_packet *packet, int version){
	packet->type = (version == 4)?ICMP_ECHOREPLY:ICMP6_ECHO_REPLY;
}

/*
* Funkce na zavření socketu
*/
void close_icmp_socket(int sock_id){
	close(sock_id);
}

uint16_t in_cksum(uint16_t *addr, int len)
{	

	printf("LEN = %d\n", len);
	assert(len >= 0);
	
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *addr++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)addr;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;
	
	printf("CHECKSUM:    %x\n", ret);

	return ret; 
}

uint16_t in6_cksum(struct ip6_hdr *ip6, uint16_t *payload, int payload_size){

	uint8_t *pseu_hdr = (uint8_t *)malloc(PSEU_HDR_LEN * sizeof(uint8_t));

	memset(pseu_hdr, 0, PSEU_HDR_LEN);

	uint8_t *src_addr = pseu_hdr;
	uint8_t *dst_addr = pseu_hdr + 16;
	uint8_t *icmpv6_len = pseu_hdr + 32;
	uint8_t *nxt_hdr = pseu_hdr + 39;
	
	memcpy(src_addr, (const char *)ip6->ip6_src.s6_addr, sizeof(ip6->ip6_src.s6_addr));
	memcpy(dst_addr, (const char *)ip6->ip6_dst.s6_addr, sizeof(ip6->ip6_dst.s6_addr));

	*icmpv6_len = payload_size / 256;
	icmpv6_len++;
	*icmpv6_len = payload_size % 256;

	*nxt_hdr = IPPROTO_ICMPV6 % 256;

	BIO_dump_fp(stdout, (const char *)pseu_hdr, PSEU_HDR_LEN);

	uint8_t *cksum_buff = (uint8_t *)malloc((PSEU_HDR_LEN + payload_size) * sizeof(uint8_t));
	memset(cksum_buff, 0, PSEU_HDR_LEN + payload_size);
	memcpy(cksum_buff, pseu_hdr, PSEU_HDR_LEN);
	memcpy(cksum_buff + PSEU_HDR_LEN, payload, payload_size);

	printf("%d + %d = %d\n", PSEU_HDR_LEN, payload_size, PSEU_HDR_LEN + payload_size);
	
	BIO_dump_fp(stdout, (const char *)cksum_buff, PSEU_HDR_LEN + payload_size);

	uint16_t icmpv6_cksum = in_cksum((uint16_t *)cksum_buff, PSEU_HDR_LEN + payload_size);
	free(cksum_buff);
	free(pseu_hdr);
	return icmpv6_cksum;
}

uint16_t
icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen) {

  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) / 256;
  ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) % 256;
  ptr++;
  chksumlen += 4;

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy ICMPv6 type to buf (8 bits)
  memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
  ptr += sizeof (icmp6hdr.icmp6_type);
  chksumlen += sizeof (icmp6hdr.icmp6_type);

  // Copy ICMPv6 code to buf (8 bits)
  memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
  ptr += sizeof (icmp6hdr.icmp6_code);
  chksumlen += sizeof (icmp6hdr.icmp6_code);

  // Copy ICMPv6 ID to buf (16 bits)
  memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
  ptr += sizeof (icmp6hdr.icmp6_id);
  chksumlen += sizeof (icmp6hdr.icmp6_id);

  // Copy ICMPv6 sequence number to buff (16 bits)
  memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
  ptr += sizeof (icmp6hdr.icmp6_seq);
  chksumlen += sizeof (icmp6hdr.icmp6_seq);

  // Copy ICMPv6 checksum to buf (16 bits)
  // Zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy ICMPv6 payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
  }

  return in_cksum ((uint16_t *) buf, chksumlen);
}


void prepare_hdr(struct iphdr *ip, struct icmphdr *icmp, int seq){
	
	ip->version = 4;	
	ip->ihl = 5;
	ip->tos = 0;
	ip->id = seq;
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_ICMP;

	prepare_icmp(icmp, seq);
}

void prepare_icmp(struct icmphdr *icmp, int seq){

	icmp->code = 0;
	icmp->un.echo.sequence = seq;
	icmp->un.echo.id = 256;
	icmp->checksum = 0;
}
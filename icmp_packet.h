#ifndef ICMP_PACKET
#define ICMP_PACKET

#include <stdint.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define MTU 			1450	// Maximální velikost paketu
#define MAX_PYLD_SIZE 	(MTU - sizeof(struct iphdr) - sizeof(struct icmphdr) - sizeof(struct s_icmp_file_info) - 58) // Maximální velikost payloadu
#define MAX_FILENAME 	32 		// Maximální délka názvu souboru
#define KEY 			"xhlavk09" // Klíč k šifrování
#define KEY_SIZE 		32 			// Velikost klíče
#define IV_SIZE			KEY_SIZE/2 	// Velikost inicializačního vektoru
#define IPV6_HDRINCL	36 
#define PSEU_HDR_LEN	40	// Velikost ipv6 pseudohlavičky pro výpočet checksum

#define OK_REPLY		10
#define FILE_MV			1
#define HOP_LIMIT		239

// Struktura pro jednodušší přenost důležitých dat mezi funkcemi
struct icmp_packet
{
	char src_addr[100];
	char dest_addr[100];
	int type;
	unsigned char* payload;
	int payload_size;
	uint8_t file_type;
	uint32_t order;
	int cipher_len;
	uint32_t count;
	int part_size;
	int src_len;
	int seq;
	unsigned char iv[IV_SIZE];
	char filename[MAX_FILENAME];
};

// Struktura definující protokol pro kontrolu přenosu souboru
struct s_icmp_file_info
{
	uint8_t type;
	uint32_t order;
	int cipher_len;
	int count;
	int part_size;
	int src_len;
	unsigned char iv[IV_SIZE];
	char filename[MAX_FILENAME];
};


/*
* Funkce na otevření raw socketu a nastavení sokcetu
* aby bylo možné posílat ICMP pakety
* RETURNVAL - ID otevřeného soketu
*/
int open_icmp_socket(int version, int server);

/*
* Funkce na nastevení poslouchání na soketu na danou adressu
* (INADDR_ANY = jakákoliv)
* sock_id - ID socketu na kterém bude program přijímat pakety
*/
void bind_icmp_socket(int sock_id, int version);

/*
* Nastení paketu na ECHO type
* packet - struktura pro držení detailů paketu
*/
void set_echo_type(struct icmp_packet *packet, int version);

/*
* Nastení paketu na REPLY type
* packet - struktura pro držení detailů paketu0
*/
void set_reply_type(struct icmp_packet *packet, int version);

/*
* Funkce na poslání ICMP paketu
* sock_id 			- ID socketu
* packet_details 	- struktura pro detaily ICMP paketu
*/
void send_icmp_packet(int sock_id, struct icmp_packet *packet_details, int version);

/*
* Funkce na přijímání ICMP paketu
* sock_id 			- ID socketu
* packet_details 	- struktura pro detaily ICMP paketu
*/
void recieve_icmp_packet(int sock_id, struct icmp_packet *packet_details, int version);

/*
* Funkce na zavření socketu
* socket_id - ID socketu
*/
void close_icmp_socket(int socket_id);

#endif //ICMP_PACKET
#ifndef PACKET_HANDLE
#define PACKET_HANDLE

#include "icmp_packet.h"

#define DEBUG printf("Hello %d\n", __LINE__);	// Pomoc při debuggování

/*
* Funkce na rozdělení pole na části specifické velikosti
* payload - zdrojové pole
* payload_size - velikost zdrojového pole
* count - proměnná pro vrácení počtu nových polí
* last_size - velikost poslední části
* RETURNVAL - pole rozdělených polí
*/
unsigned char** divide_payload(unsigned char* payload, int payload_size,
	uint32_t *count, int *last_size);

/*
* Funkce na spojení menších polí do jednoho velkého
* source - pole polí pro sloučení
* count - počet menších polí
* last_size - velikost posledního pole
* RETURNVAL - výsledné sloučené pole
*/
unsigned char* marge_payload(unsigned char **source, uint32_t count, int last_size);

/*
* Funkce na generování náhodných znaků do pole
* buff - zdrojové pole na vyplnění
* size - velikost zdrojového pole
*/
void random_char_array_gen(unsigned char *buff, int size);

/*
* Funkce na zašifrování/rozšifrování zdrojového pole
* src_char - zdrojové pole
* dst_char - cílové pole
* mode - druh šifrování (0 = zašifrování / 1 = dešifrování)
* src_len - délka zdrojového pole
* iv_in - inicializační vektor
* RETURNVAL - délka výsledného pole po šifrování
*/
int aes_encryption(unsigned char* src_char, unsigned char *dst_char,
	int mode, int src_len, unsigned char *iv_in);

/*
* Funkce na uvolnění místa v paměti pro pole polí
* buff - ukazatel na uvolnění
* buff_cnt - počet dílčích polí
*/
void free_file_buff(unsigned char **buff, int buff_cnt);

/*
* Funkce na odeslání celého souboru po jednotlivých paketech
* src - zdrojová adresa
* dst - cílová adresa
* payload - data pro přenesení
* filename - název souboru pro přenesení
* payload_size - velikost dat pro přenesení
* version - ipv4 nebo ipv6 pakety
*/
void send_icmp_file(char *src, char *dst, char *payload,
	char *filename, int payload_size, int version);

#endif //PACKET_HANDLE
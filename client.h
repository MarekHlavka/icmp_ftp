#ifndef CLIENT
#define CLIENT

#include "icmp_packet.h"
#include "file_handle.h"
#include "packet_handle.h"

/* Hlavní funkce na spuštění běhu klienta
* server_address - Cílová adresa zasílaných paketů
* src_filename - název zdrojového souboru
*/
void run_client(char *server_address, char *src_filename);

#endif //CLIENT
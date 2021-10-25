#include "client.h"
#include <netdb.h>
#include <stdlib.h>

#define MAX_ADDR_LEN	256

void address_lookup(){}

void run_client(char *address, char *src_filename){

	char *payload;
	char src_ip[MAX_ADDR_LEN];
	char dst_ip[MAX_ADDR_LEN];
	struct hostent *dst_hstmn;
	struct hostent *src_hstmn;
	int payload_len;



	dst_hstmn = gethostbyname(address);
	strcpy(dst_ip, inet_ntoa(*((struct in_addr*)dst_hstmn->h_addr_list[0])));

	// possible change
	src_hstmn = gethostbyname("0.0.0.0");
	strcpy(src_ip, inet_ntoa(*((struct in_addr*)src_hstmn->h_addr_list[0])));

	payload = read_file_as_byte_array(src_filename, &payload_len);

	send_icmp_file(src_ip, dst_ip, payload, src_filename, payload_len);

}
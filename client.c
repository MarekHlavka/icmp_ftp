#include "client.h"
#include <netdb.h>
#include <stdlib.h>

#define MAX_ADDR_LEN	256

void run_client(char *address, char *src_filename){

	char *payload;
	char src_ip[MAX_ADDR_LEN];
	char dst_ip[MAX_ADDR_LEN];
	struct hostent *dst_hstmn;
	struct hostent *src_hstmn;



	dst_hstmn = gethostbyname(address);
	strcpy(dst_ip, inet_ntoa(*((struct in_addr*)dst_hstmn->h_addr_list[0])));

	src_hstmn = gethostbyname("0.0.0.0");
	strcpy(src_ip, inet_ntoa(*((struct in_addr*)src_hstmn->h_addr_list[0])));

	payload = read_file_as_byte_array(src_filename);

	send_icmp_file(src_ip, dst_ip, payload, src_filename);
	/*

	packet.payload_size = strlen(packet.payload);
	packet.file_type = 1;
	packet.order = 0;
	memcpy(packet.filename, src_filename, sizeof(src_filename));



	char **buff = divide_payload(packet.payload, packet.payload_size,
		MAX_PYLD_SIZE/10, &packet_count);

	packet.payload = buff[0];

	printf("%d\n", packet_count);

	socket_id = open_icmp_socket();

	printf("Sending...\n%s\n", packet.payload);
	send_icmp_packet(socket_id, &packet);
	printf("Closing...\n");
	close_icmp_socket(socket_id);
	*/

}
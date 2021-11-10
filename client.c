#include "client.h"
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_ADDR_LEN	256

int lookup_host (const char *host, char* dst)
{
  struct addrinfo hints, *res, *result;
  int errcode;
  char addrstr[MAX_ADDR_LEN];
  void *ptr;
  int ip_ver;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo (host, NULL, &hints, &result);
  if (errcode != 0)
    {
      perror ("getaddrinfo");
      return -1;
    }
  
  res = result;
  inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, MAX_ADDR_LEN);
  switch (res->ai_family)
    {
    case AF_INET:
      ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
      ip_ver = 4;
      break;
    case AF_INET6:
      ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
      ip_ver = 6;
      break;
    }
  inet_ntop (res->ai_family, ptr, addrstr, MAX_ADDR_LEN);
  memcpy(dst, addrstr, MAX_ADDR_LEN);
  freeaddrinfo(result);

  return ip_ver;
}

void run_client(char *address, char *src_filename){

	char *payload;
	char dest[MAX_ADDR_LEN];
	char src_ip[MAX_ADDR_LEN];
	int payload_len;

	int ip_version = lookup_host(address, dest);
	if(ip_version == -1){
		perror("Wrong address format");
		exit(-1);
	}
	if(ip_version == 4){
		strcpy(src_ip, "0.0.0.0");
	}
	else{
		strcpy(src_ip, "2a02:8308:b086:c00:60c2:23ea:bb6a:b4de");		
	}

  payload = read_file_as_byte_array(src_filename, &payload_len);
	send_icmp_file(src_ip, dest, payload, src_filename, payload_len, ip_version);

}

#include "server.h"
#include "client.h"
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>

#define WRONG_PARAMS	30
#define SUCESS			0

/* Usage: 
	secret -r <file> -s <ip|hostname> [-l]
		-r <file> : specifikace souboru pro přenos
		-s <ip|hostname> : ip adresa/hostname na kterou se má soubor zaslat
		-l : pokud je program spuštěn s tímto parametrem, jedná se o server,
			který naslouchá příchozím ICMP zprávám a ukládá soubor do stejného adresáře,
			kde byl spuštěn.

*/
void print_usage(){
	printf("Run:\n \
		secret -r <file> -s <ip|hostname> [-l]\n\n \
		-r <file> : specifikace souboru pro přenos\n \
		-s <ip|hostname> : ip adresa/hostname na kterou se má soubor zaslat\n \
		-l : pokud je program spuštěn s tímto parametrem, jedná se o server,\n \
			který naslouchá příchozím ICMP zprávám a ukládá soubor do stejného adresáře,\n \
			kde byl spuštěn.\n"
		);
}

int main(int argc, char** argv){

	int argument;
	bool file_flag, ip_flag, server_flag = false;
	char filename[256];
	char address[64];

	while((argument = getopt(argc, argv, ":r:s:l")) != -1){
		switch(argument){
			case 'r':
				file_flag = true;
				strcpy(filename, optarg);
				break;
			case 's':
				ip_flag = true;
				strcpy(address, optarg);
				break;
			case 'l':
				server_flag = true;
				break;
		}
	}
	if(optind < argc){
		print_usage();
		exit(WRONG_PARAMS);
	}

	printf("File argument: %s\n%s\n",file_flag ? "true" : "false", filename);
	printf("IP argument: %s\n%s\n",ip_flag ? "true" : "false", address);
	printf("Server argument: %s\n",server_flag ? "true" : "false");


	/*
	if(argc == 2){
		run_client();
		return 0;
	}
	else{
		run_server();
		return 0;
	}
	*/
	return 0;

}
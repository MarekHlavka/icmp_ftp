
#include "server.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* Usage: 
	secret -r <file> -s <ip|hostname> [-l]
		-r <file> : specifikace souboru pro přenos
		-s <ip|hostname> : ip adresa/hostname na kterou se má soubor zaslat
		-l : pokud je program spuštěn s tímto parametrem, jedná se o server,
			který naslouchá příchozím ICMP zprávám a ukládá soubor do stejného adresáře,
			kde byl spuštěn.

*/
int main(int argc, char** argv){

	int argument;

	while((argument = getopt(argc, argv, "r:s:l")) != -1){
		break;
	}

	if(argc == 2){
		run_client();
		return 0;
	}
	else{
		run_server();
		return 0;
	}

}
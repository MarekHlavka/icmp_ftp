
#include "server.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char** argv){

	if(argc == 2){
		run_client();
		return 0;
	}
	else{
		run_server();
		return 0;
	}

}
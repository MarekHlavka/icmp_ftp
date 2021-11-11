#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


#define WRITE_SIZE 100	// Velikost jednoho zápisu do souboru

/*
* Funkce na načtení libovolného souboru jako bajtového pole - nezávislé na příponě
*/
char* read_file_as_byte_array(char* filename, int *payload_len){

	FILE *fileptr;	// Soubor
	char *buffer;	// cílové pole
	long filelen;	// délka načteného pole

	fileptr = fopen(filename, "rb");
	if(fileptr == NULL){
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}
	fseek(fileptr, 0, SEEK_END);	// Nalezení konce souboru
	filelen = ftell(fileptr);		// Výpočet délky souboru
	rewind(fileptr);				// Vrácení ukazatele na začátek souboru

	buffer = (char *)malloc(filelen * sizeof(char));
	fread(buffer, filelen, 1, fileptr);	// Načtení souboru
	*payload_len = filelen; 
	fclose(fileptr);
	return buffer;

}

/*
* Funkce na zapsání bajtového pole do souboru
*/
void write_file_as_byte_array(char* filename, unsigned char* src, int src_len){

	printf("Writing file\n");

	FILE *fileptr;

	// Určení informací pro cyklické zapisování
	uint32_t loop = src_len / WRITE_SIZE;
	uint32_t last = src_len % WRITE_SIZE;
	unsigned char* buff = src;

	fileptr = fopen(filename, "wb+");
	if(fileptr == NULL){
		perror("Error creating file!");
		exit(EXIT_FAILURE);
	}

	// Cyklický zápis do souboru - zápis v kuse potřebuje příliš zdrojů zařízení
	for(uint32_t i = 0; i < loop; i++){
		fwrite((char *)buff, 1, WRITE_SIZE, fileptr);
		buff += WRITE_SIZE;
	}
	fwrite((char *)buff, 1, last, fileptr);
	fclose(fileptr);

}

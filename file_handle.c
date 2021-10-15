#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

	FILE *fileptr;
	char new_name[80] = "New";
	strcat(new_name, filename);

	fileptr = fopen(new_name, "wb+");
	if(fileptr == NULL){
		perror("Error creating file!");
		exit(EXIT_FAILURE);
	}
	fwrite((char *)src, 1, src_len, fileptr);
	fclose(fileptr);

}

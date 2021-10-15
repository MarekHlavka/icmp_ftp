#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char* read_file_as_byte_array(char* filename){

	FILE *fileptr;
	char *buffer;
	long filelen;

	fileptr = fopen(filename, "rb");
	if(fileptr == NULL){
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	buffer = (char *)malloc(filelen * sizeof(char));
	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;

}

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

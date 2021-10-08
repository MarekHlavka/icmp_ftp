#include <stdlib.h>
#include <stdio.h>

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
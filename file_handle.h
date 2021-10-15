#ifndef FILE_HANDLE
#define FILE_HANDLE

char* read_file_as_byte_array(char* filename);

void write_file_as_byte_array(char* filename, unsigned char* src, int src_len);

#endif //FILE_HANDLE
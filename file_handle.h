#ifndef FILE_HANDLE
#define FILE_HANDLE

/*
* Funkce na načtení libovolného souboru jako bajtového pole - nezávislé na příponě souboru
* filename		- Název zdrojového souboru
* payload_len 	- Ukazatel na uložení délky načteného souboru
* RETURNVAL		- pole bajtů, načtené ze souboru
*/
char* read_file_as_byte_array(char* filename, int *payload_len);

/*
* Funkce na zapsání bajtového pole do souboru
* filename		- Název cílového souboru, pokud takový soubor již existuje,
*					je přepsán
* src_len		- Délka zapisovaného pole
*/
void write_file_as_byte_array(char* filename, unsigned char* src, int src_len);

#endif //FILE_HANDLE
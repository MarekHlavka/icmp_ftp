#ifndef AES
#define AES

#define AES_ENCRYPT	0
#define AES_DECRYPT	1

/*
*	Funkce na zašifrování zdrojového pole
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);

/*
*	Funkce na dešifrování zašifrovaného pole
*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext);

#endif //AES
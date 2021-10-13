#ifndef AES
#define AES

#define AES_ENCRYPT	0
#define AES_DECRYPT	1

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext);

#endif //AES
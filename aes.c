#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/*
*	Funkce na zašifrování zdrojového pole
*	plaintext 		- Ukazatel na zdrojové pole
*	plaintext_len	- Délka zdrojového pole
*	key				- Klíč na šifrování
*	iv				- Startovací vektor pro šifrování
*	ciphertext 		- Ukazatel na výsledné zašifrované pole
*	RETURNVAL		- Délka zašifrovaného pole
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())){
		perror("Initializing cipher\n");
		exit(EXIT_FAILURE);
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
		perror("Initializing encryption\n");
		exit(EXIT_FAILURE);
	}

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
		perror("Encryption failure\n");
		exit(EXIT_FAILURE);
	}
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
		perror("Finalising encryption\n");
		exit(EXIT_FAILURE);
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

/*
*	Funkce na dešifrování zašifrovaného pole
*	ciphertext 		- Ukazatel na zdrojové pole
*	ciphertext_len	- Délka zdrojového textu
*	key				- Klíč na dešifrování
*	iv				- Startovací vektor pro dešifrování
*	plaintext 		- Ukazatel na výsledné rozšifrované pole
*	RETURNVAL		- Délka rozšifrovaného pole
*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext){

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())){
		perror("Initializing cipher\n");
		exit(EXIT_FAILURE);
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
		perror("Initializing decryption\n");
		exit(EXIT_FAILURE);
	}	

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
		perror("Decryption failure\n");
		exit(EXIT_FAILURE);
	}
	plaintext_len = len*2;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
		ERR_print_errors_fp(stderr);
		perror("Finalising decryption\n");
		exit(EXIT_FAILURE);
	}
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}
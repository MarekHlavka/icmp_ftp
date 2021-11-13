#include "server.h"

// Spuštění serveru pro specifickou verzi paketů
void run_version(int ver){

	struct icmp_packet packet;
	int socket_id;

	socket_id = open_icmp_socket(ver, 1);
	bind_icmp_socket(socket_id, ver);


	uint32_t packet_count = 0;
	int last_size = 0;
	int cipher_len = 0;
	int original_size = 0;
	unsigned char iv[IV_SIZE];
	char filename[MAX_FILENAME];

	// Cyklus pro nekonečný běh serveru
	while(1){

		// Přijímaní prvního paketu
		do{
			recieve_icmp_packet(socket_id, &packet, ver);
		}while(packet.file_type != FILE_MV);

		unsigned char *buff[packet.count];

		cipher_len = packet.cipher_len;
		original_size = packet.src_len;
		memcpy(iv, packet.iv, IV_SIZE);
		memcpy(filename, packet.filename, MAX_FILENAME);

		// Cyklus pro přijímaní paketu pro momentálně přenášený soubor
		// Ostatní pakety stejného druhu jsou zahozeny
		while(1){

			// Alokace paměti
			buff[packet.order] = (unsigned char *)malloc(packet.part_size * sizeof(unsigned char));
			if(buff[packet.order] == NULL){
					perror("No memory available \n");
					close_icmp_socket(socket_id);
					exit(-1);
			}

			memcpy(buff[packet.order], packet.payload, packet.part_size);
			packet_count++;
			free(packet.payload);

			if(packet.order == packet_count -1){
				last_size = packet.part_size;
			}
			// Kontrola zda jsou všechny pakety přeneseny
			if(packet.count == packet_count){
				break;
			}

			// Přijímaní dalších paketů aktuálně přenášeného souboru
			do{
				recieve_icmp_packet(socket_id, &packet, ver);
			}while(packet.file_type != FILE_MV || packet.type == (ver == 4? ICMP_ECHOREPLY:ICMP6_ECHO_REPLY) || strcmp(filename, packet.filename) != 0);

		}

		// Sloučení veškerých dat souboru
		unsigned char *merged_buff = marge_payload(buff, packet_count, last_size);
		// Alokace paměti před dešifrováním
		unsigned char *decrypted = (unsigned char *)malloc(original_size * sizeof(unsigned char) * 4);
		unsigned char *original = (unsigned char *)malloc(original_size * sizeof(unsigned char));

		if(decrypted == NULL){
			perror("No memory available 1\n");
			close_icmp_socket(socket_id);
			exit(-1);
		}
		// Dešifrování dat
		aes_encryption(merged_buff, decrypted, AES_DECRYPT, cipher_len, iv);
		memcpy(original, decrypted, original_size);

		// Zapsaní dat do souboru ve složce, kde je aplikace spuštěna
		write_file_as_byte_array(filename, original, original_size);
		
		// Uvolnění zdrojů aktuálního souboru
		for(uint32_t i = 0; i < packet_count; i++){
			free(buff[i]);
		}
		
		free(original);
		free(decrypted);
		free(merged_buff);
		printf("File: %s saved...\n", filename);
		packet_count = 0;
	}

	close_icmp_socket(socket_id);
	
}
void *run_server_4(){
	run_version(4);
	return NULL;
}
void *run_server_6(){
	run_version(6);
	return NULL;
}

void run_server(){

	pthread_t ver_4, ver_6;
	pthread_create(&ver_4, NULL, run_server_4, NULL);
	pthread_create(&ver_6, NULL, run_server_6, NULL);

	pthread_join(ver_4, NULL);
	pthread_join(ver_6, NULL);

}
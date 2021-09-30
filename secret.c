//
// Created by marek on 30.09.2021.
//

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/sockets.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define CLIENT_MODE = 0
#define SERVER_MODE = 1

#define DEF_PORT = 9245

int main(int argc, char *argv[]) {

    // Client
    if (argv[1] == CLIENT_MODE) {}    // create a socket
        int my_socket;
        my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        // adresa socketu
        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons( DEF_PORT);
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);

        int connection_status = connect(my_socket, (struct sockaddr *) &server_address, sizeof(server_address));
        if (connection_status == -1) {
            printf("Error making connection");
        }

        // prijimat data
        char server_response[256];
        recv(my_socket, &server_response, sizeof(server_response), 0);

        print("Response: %s", server_response);

        close(my_socket);
    }
    // Server
    else{
        char server_message[256] = "You have reached the server!";

        // create server socket
        int server_socket;
        server_socket = socket(AF_INET)
    }

    return 0;
}


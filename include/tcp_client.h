#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <iostream>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class tcp_client {

    private:
        int socket_fd;
        struct sockaddr_in server_addr;

    public:        
        tcp_client();
        bool establish_connection(const char* addr, uint16_t port);
        bool send_message(const char* message, int length);
        void end_connection();
        int wait_for_response(uint8_t* &buff);
};

#endif

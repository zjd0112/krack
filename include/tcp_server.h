#ifndef TCP_SERVER_H
#define TCP_SREVER_H

#include <iostream>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "json/json.h"

class tcp_server {

    private:
        uint16_t port;
        int socket_fd;
        int connect_fd;
        struct sockaddr_in server_addr;
        struct sockaddr_in client_addr;

        int recv_message(uint8_t* &buff);
        void data_process(uint8_t* buff, int buff_len);
        bool send_response(uint8_t* message, int message_len);

    public:
        int r;
        int state;  // different state
        tcp_server();
        tcp_server(uint16_t);
        bool start_server();
        void start_listening();
};

#endif

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
#include <string>

#include "json/json.h"
using namespace std;

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
        string MAC;
        int Nonce;
        bool start_transfer_flag;
        string TK;
        uint8_t *ANonce;
        string str_masterKey;
        uint8_t r;
        int state;  // different state
        tcp_server();
        tcp_server(uint16_t);
        bool start_server();
        void start_listening();
        void output_hex_string(const char* str);
        string get_stream_cipher();
        string get_plain_text(string cipher_text);
};

#endif

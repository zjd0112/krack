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
        bool resent_msg4_flag;
        bool start_transfer_flag;
        bool wait_for_msg4_flag;
        uint8_t *ANonce;
        uint8_t r;
        int Nonce;        
        int start_timestamp;
        int state;  // different state
        string MAC;
        string TK;
        string str_masterKey;
        tcp_server();
        tcp_server(uint16_t);
        bool start_server();
        void start_listening();
        void output_hex_string(const char* str);
        void output_hex_string_withlen(const char* str, int len);
        string get_stream_cipher();
        string get_plain_text(string cipher_text, int len);
};

#endif

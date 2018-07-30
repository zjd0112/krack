#ifndef TCP_ADVERSARY_H
#define TCP_ADVERSARY_H

#include <string>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vector>

#include "tcp_client.h"

using namespace std;

class tcp_adversary {
    private:
        string str_ap_ip;
        uint16_t port_adver;
        uint16_t port_ap;
        int socket_client;
        int socket_AP;
        int connect_fd_client;
        int connect_fd_AP;
        struct sockaddr_in adversary_addr;
        struct sockaddr_in server_addr;
        struct sockaddr_in client_addr;
        tcp_client client;
        int r;
        bool isMsg4;
        bool isMsg4Arrived;
        bool isMsg4ArrivedAgain;
        vector<string> vec_mesg_before;
        vector<string> vec_mesg_after;

        int recv_message(uint8_t* &buff);
        void data_process(uint8_t* buff, int buff_len);
        bool send_response(int connect_fd_resp, uint8_t* message, int message_len);

    public:
        tcp_adversary(string str_ap_ip, uint16_t port_adver, uint16_t port_ap);
        bool start_adversary();
        void start_listening();


};

#endif

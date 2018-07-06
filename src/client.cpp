#include <iostream>

#include "tcp_client.h"

using namespace std;

string str_auth = "Authentication_Request";

int main(int argc, char* argv[])
{
    if (argc < 5)
    {
        printf("Usage: ./client AP_IP AP_PORT MasterKey data_file\n");
        printf("Exampele: ./client 127.0.0.1 1234 1111 Packet.txt\n");
        return 0;
    }

    string str_ap_ip;
    uint16_t ap_port = 0;
    string str_masterKey;
    string str_filePath;
    tcp_client client;

    str_ap_ip = argv[1];
    ap_port = (uint16_t)atoi(argv[2]);
    str_masterKey = argv[3];
    str_filePath = argv[4];

    client.establish_connection(str_ap_ip.c_str(), ap_port);
    client.send_message(str_auth.c_str(), str_auth.length());

    uint8_t* buff;
    int response_len = client.wait_for_response(buff);
    for (int count = 0; count < response_len; count++)
    {
        printf("%02x", buff[count]);
    }
    printf("\n");
    
    delete[] buff;

    client.end_connection();
    return 0;
}

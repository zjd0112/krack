#include <iostream>

#include "tcp_client.h"
#include "rander.h"

#define CNONCE_LEN 4

using namespace std;

string str_auth = "Authentication_Request";
uint8_t r;

void output_hex_string(const char* str){
    for (int count = 0; count < strlen(str); count++){
        printf("%02x", (unsigned char)str[count]);
    }
    printf("\n");    
}

int main(int argc, char* argv[])
{
    if (argc < 5)
    {
        printf("Usage: ./client AP_IP AP_PORT MasterKey data_file\n");
        printf("Example: ./client 127.0.0.1 1234 1111 Packet.txt\n");
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
    
    // 1. authentication request
    client.send_message(str_auth.c_str(), str_auth.length());

    // receive ANonce
    printf("Receive ANonce: ");
    uint8_t* buff;// ANonce + r
    int response_len = client.wait_for_response(buff);
    char* ANonce = new char[response_len-1];
    strncpy(ANonce, (char*)buff, response_len-1);
    output_hex_string((char*)ANonce);
    r = buff[response_len-1];    
    printf("Receive r: %d\n", r);
    delete[] buff;            
    sleep(1);
    
    // 4. generate CNonce
    printf("Generate CNonce: ");
    rander myRander;
    unsigned char CNonce[CNONCE_LEN];
    myRander.get_random(CNonce, CNONCE_LEN);
    output_hex_string((char*)CNonce);
    
    // 5. calculate TK
    printf("TK: ");
    string TK = ANonce + string((char*)CNonce) + str_masterKey.c_str();
    output_hex_string(TK.c_str());

    // 6. send Msg2(r, CNonce)
    unsigned char* msg2 = new unsigned char[CNONCE_LEN+1];
    strcpy((char*) msg2, (char*) CNonce);
    msg2[CNONCE_LEN] = r;
    client.send_message((char*)msg2, strlen((char*)msg2));

    client.end_connection();
    return 0;
}

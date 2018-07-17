#include <iostream>

#include "tcp_client.h"
#include "rander.h"

#define CNONCE_LEN 4

using namespace std;

string str_auth = "Authentication_Request";
uint8_t r;
string MAC;
int Nonce;
string TK;

void output_hex_string(const char* str){
    for (int count = 0; count < strlen(str); count++){
        printf("%02x", (unsigned char)str[count]);
    }
    printf("\n");    
}

string get_stream_cipher(){
    string IV = MAC + to_string(Nonce);
    string tmp_cipher = IV + TK;
    char tmp_2_cipher[16];
    strncpy(tmp_2_cipher, tmp_cipher.c_str(), 16);
    string stream_cipher = tmp_2_cipher;
    Nonce++;
    return stream_cipher;
}

string send_cipher(string plain_text){            
    printf("plain text in hex:\n");
    output_hex_string(plain_text.c_str());
    printf("plain text:\n");
    cout<<plain_text<<endl;

    string final_cipher = "";
    int length = plain_text.length();
    int pointer = 0;
    // printf("length: %d\n", length);
    while(pointer < length){
        string stream_cipher = get_stream_cipher();
        string plain_block;
        string plain_block_tmp;
        if(pointer + 16 >= length){
            plain_block_tmp = plain_text.substr(pointer, length-pointer);
            unsigned char* final_plain_block = new unsigned char[16];            
            for(int j=0; j<16; j++){
                final_plain_block[j]=0x00;
            }
            for(int j=0; j < plain_block_tmp.length(); j++){
                final_plain_block[j] = plain_block_tmp[j];
            }
            /*
            // don't remove this block
            for(int j=0; j<16; j++){                
                printf("%02x", final_plain_block[j]);
            }printf("\n");            
            */
            plain_block = string((char*)final_plain_block);
        }else{
            plain_block = plain_text.substr(pointer, 16);            
        }
        // EOR between plain_block and stream_cipher
        string cipher_block = "";
        for(int i = 0 ; i < 16; i++){
            cipher_block = stream_cipher[i]^plain_block[i];
            final_cipher += cipher_block;
        }        
        pointer += 16;
    }

    printf("cipher text:\n");
    output_hex_string(final_cipher.c_str());
    return final_cipher;
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
    TK = ANonce + string((char*)CNonce) + str_masterKey.c_str();
    output_hex_string(TK.c_str());

    // 6. send Msg2(r, CNonce)
    unsigned char* msg2 = new unsigned char[CNONCE_LEN+1];
    strcpy((char*) msg2, (char*) CNonce);
    msg2[CNONCE_LEN] = r;
    client.send_message((char*)msg2, strlen((char*)msg2));

    // 8. receive Msg3
    response_len = client.wait_for_response(buff);
    if(buff[0] == '~'){
        printf("ACK is received, and r is %d\n", buff[1]);
        r = buff[1];
    }

    // 9. send Msg4
    uint8_t* msg4 = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
    msg4[0] = '~';
    msg4[1] = r;
    client.send_message((char*)msg4, 2); // send

    // 10. init encryption

    Nonce = 0;
    MAC = "3A3D72843A";

    // 11. data transfer
    while(true){
        sleep(1);
        // cipher_text end with '`'
        string cipher_text = send_cipher("We were both young when I first saw you I close my eyes and the flashback starts I'm standing there on a balcony in summer air See the lights see the party the ball gowns See yo`");
        char* cipher_text_2 = new char[cipher_text.length()+1];
        cipher_text_2 = (char*)cipher_text.c_str();
        cipher_text_2[cipher_text.length()] = 2;
        client.send_message((char*)cipher_text_2, cipher_text.length()+1); // send
        break;
    }
    client.end_connection();
    return 0;
}


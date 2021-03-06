// if you want to restart Client, AP need to be restarted as well, or the Nonce would be different.

#include <iostream>
#include <cassert>
#include <fstream>

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

void output_hex_string_withlen(const char* str, int len){
    for (int count = 0; count < len; count++){
        printf("%02x", (unsigned char)str[count]);
    }
    printf("\n");    
}

string get_stream_cipher(){
    string IV = MAC + to_string(Nonce);
    string tmp_cipher = IV + TK;
    char tmp_2_cipher[17];
    tmp_2_cipher[16]='\0';
    strncpy(tmp_2_cipher, tmp_cipher.c_str(), 16);
    string stream_cipher = tmp_2_cipher;
    Nonce++;
    return stream_cipher;
}

string get_cipher_text(string plain_text){            
    puts("----------");
    // printf("PLAIN TEXT IN HEX:\n");
    // output_hex_string(plain_text.c_str());
    printf("PLAIN TEXT:\n");
    cout<<plain_text<<endl;

    string final_cipher = "";
    int length = plain_text.length();
    int pointer = 0;
    while(pointer < length){
        string stream_cipher = get_stream_cipher();
        string plain_block;
        string plain_block_tmp;
        if(pointer + 16 >= length){ // the last plain block that is less than 16 bytes
            plain_block_tmp = plain_text.substr(pointer, length-pointer);
            unsigned char* final_plain_block = new unsigned char[16];            
            for(int j=0; j<16; j++){
                final_plain_block[j]=0x00;
            }
            for(int j=0; j < plain_block_tmp.length(); j++){
                final_plain_block[j] = plain_block_tmp[j];
            }
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
    
    printf("CIPHER TEXT:\n");
    output_hex_string_withlen(final_cipher.c_str(), final_cipher.length());
    printf("Nonce: %d\n", Nonce);
    return final_cipher;
}

string read_txt(string file){
        ifstream infile;
        infile.open(file.data());
        assert(infile.is_open());

        string s;
        string fianl_str = "";
        while(getline(infile, s)){
                fianl_str += s;
        }        
        infile.close();        
        return fianl_str;
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
    client.send_message((char*)msg2, CNONCE_LEN+1);

    // 8. receive Msg3
    response_len = client.wait_for_response(buff);
    // printf("receive msg3 buff[0] is: %c\n",buff[0]);
    if(buff[0] == '~'){
        printf("receive r: %d\n", buff[1]);
        r = buff[1];
    }

    // 9. send Msg4. DONT'T REMOVE THIS BLOCK. 
    // you can remove the block comment to avoid the loss of msg4.
    
    uint8_t* msg4 = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
    msg4[0] = '~';
    msg4[1] = r;
    printf("client send msg4 r: %d\n", r);
    client.send_message((char*)msg4, 2); // send
    

    // 10. init encryption
    Nonce = 0;
    MAC = "3A3D72843A";

    // open file
    ifstream infile;
    infile.open(str_filePath);
    assert(infile.is_open());

    string src_cipher_text;
    
    // 11. data transfer
    while(getline(infile, src_cipher_text)){
        sleep(1);             

        // cipher_text end with '`'        
        string cipher_text = get_cipher_text(src_cipher_text); // end with '`'        
        char* cipher_text_2 = new char[cipher_text.length()+1];
        cipher_text_2 = (char*)cipher_text.c_str();
        cipher_text_2[cipher_text.length()] = 2;        
        client.send_message((char*)cipher_text_2, cipher_text.length()+1); // send
        
        // incase Msg3(r+2, ACK) is received
        // 13. receive Msg3(r+2, ACK)
        response_len = client.wait_for_response(buff);
        if(buff[0] == '~'){
            r = buff[1];
            printf("receive r: %d\n", r);            

            // 14. send Msg4(r+2, ACK)
            uint8_t* msg4 = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
            msg4[0] = '~';
            msg4[1] = r;
            client.send_message((char*)msg4, 2); // send   

            // 15. init encryption again
            Nonce = 0;
        }        
    }
    infile.close();
    client.end_connection();
    return 0;
}

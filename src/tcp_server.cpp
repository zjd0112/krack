#include "tcp_server.h"
#include "rander.h"

#define MAXLEN 4096
#define HEADER_LEN 4
#define ANONCE_LEN 4

using namespace std;

tcp_server::tcp_server()
{
    r = 0;
    state = 0;
    start_transfer_flag = false;
    ANonce = new uint8_t[ANONCE_LEN];
    Nonce = 0;
    MAC = "3A3D72843A";
    wait_for_msg4_flag = false;
    resent_msg4_flag = false;
}

tcp_server::tcp_server(uint16_t port)
{
    r = 0;
    state = 0;
    this->port = port;
    start_transfer_flag = false;
    ANonce = new uint8_t[ANONCE_LEN];
    Nonce = 0;
    MAC = "3A3D72843A";
    wait_for_msg4_flag = false;
    resent_msg4_flag = false;
}

bool tcp_server::start_server()
{
    // initialize
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);    // get ip address automatically
    server_addr.sin_port = htons(port);                 // set port

    // bind the locaANONCE_LENl address to the socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }

    // begin listen if there is a connection from client
    if (listen(socket_fd, 1024) < 0)
    {
        printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }
    printf("====waiting for client's rquest====\n");
    return true;
}

void tcp_server::start_listening()
{
    int data_len = 0;
    uint8_t *buff = NULL;
    unsigned int clientaddr_len = 0;
    while(true)
    {
        clientaddr_len = sizeof(client_addr);
        connect_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &clientaddr_len);
        if (connect_fd < 0)
        {
            printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
            continue;
        }

        while (true)
        {
            if(wait_for_msg4_flag == true){   
                puts("waiting for Msg4.");
                int now_timestamp = time(NULL);
                if(now_timestamp - start_timestamp > 1){ // send Msg3(r+2, ACK) when timeout
                    puts("TIME OUT!.");
                    // 13. Msg3
                    this->r = 3;
                    uint8_t* msg3 = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
                    msg3[0] = '~';
                    if(resent_msg4_flag == false)
                        send_response(msg3, 1);
                    resent_msg4_flag = true;
                }
            }
            data_len = recv_message(buff);
            if (data_len == -1)
            {
                break;
            }

            data_process(buff, data_len);

            if (buff != NULL)
            {
                delete[] buff;
                buff = NULL;
            }
            puts("----------");
        }
        close(connect_fd);
    }
    close(socket_fd);
}

int tcp_server::recv_message(uint8_t* &buff)
{
    int recv_len = 0;
    int data_len = 0;
    uint8_t buff_header[HEADER_LEN] = {0};

    // recv data length first
    recv_len = recv(connect_fd, buff_header, HEADER_LEN, 0);

    if (recv_len <= 0)  // the connection is disconnected by client
    {
        return -1;
    }
    // printf("lengh of data_length: %d\n", recv_len);
    for (int count = HEADER_LEN - 1; count >= 0; count --)
    {
        data_len = data_len*256 + buff_header[count];
    }
    buff = new uint8_t[data_len + 1];
    memset(buff, 0, sizeof(buff));

    // printf("data_len: %d\n", data_len);
    // recv real data
    recv_len = 0;
    while (true)
    {
        if (recv_len >= data_len)
        {
            break;
        }
        recv_len = recv_len + recv(connect_fd, buff+recv_len, data_len, 0);
    }

    //printf("recv_len: %d\n", recv_len);
    //printf("recv_data: %s\n", buff);
    //printf("address: %p\n", buff);
    return recv_len;
}

void tcp_server::data_process(uint8_t* buff, int buff_len)
{
    string str_buff = (char*)buff;

    if (buff_len < 0)
    {
        return;
    }      

    // 11. data transfer
    if(start_transfer_flag == true){        
        printf("cipher text:\n");
        output_hex_string_withlen((char*)buff, buff_len);
        string final_plain_text = get_plain_text((char*)buff, buff_len);
        printf("plain text in hex:\n");
        output_hex_string(final_plain_text.c_str());        
        

        //output plain text
        printf("plain text:\n");            
        int pos = final_plain_text.find_first_of('`');        
        for (int k=0; k<=pos; k++){
            printf("%c",final_plain_text[k]);
        }puts("");
        printf("Nonce: %d\n", Nonce);

        // repeat
        // response when received something
        // printf("send m\n");
        uint8_t* msg = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
        msg[0] = 'm';
        send_response(msg, 1);    
        return;
    }
    
    if (str_buff.compare("Authentication_Request") == 0)
    {
        // get request of client, send ANonce and r to client
        this->r = 1;
        this->state = 1;        
        rander myRander;        

        // 2. generate ANonce
        printf("Generate ANonce: ");
        myRander.get_random((unsigned char*)ANonce, ANONCE_LEN);
        uint8_t msg1[ANONCE_LEN+1]; // Msg1: ANonce and r.
        output_hex_string((char*)ANonce);
        strcpy((char*)msg1, (char*)ANonce);
        // output_hex_string((char*)msg1);

        // 3. send Msg1
        send_response(msg1, ANONCE_LEN);
        return;
    }
    uint8_t tmp_r = buff[buff_len-1];
    // printf("tmp_r is: %d\n", tmp_r);
    if (tmp_r == 1){
        printf("Receive CNonce: ");
        char* cnonce_tmp = new char[buff_len-1];
        strncpy(cnonce_tmp, (char*)buff, buff_len-1);
        string CNonce = (char*)cnonce_tmp;
        output_hex_string((char*)CNonce.c_str());        
        
        // 7. calculate TK        
        TK = string((char*)ANonce) + CNonce + str_masterKey; 
        printf("TK: ");
        output_hex_string(TK.c_str());

        // 8. Msg3
        this->r = 2;
        printf("Msg3 r: %d\n", this->r);
        uint8_t* msg3 = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
        msg3[0] = '~';
        send_response(msg3, 1);

        wait_for_msg4_flag = true;
        start_timestamp = time(NULL);
    } // 12. 
    else if(tmp_r >= 2){        
        if(buff[0] == '~'){
            start_transfer_flag = true;
            wait_for_msg4_flag = false;
        }
        // 10. init encryption already finished in constructor                
        else{ // print cipher_text when msg4 is not received.
            printf("cipher text ONLY:\n");
            output_hex_string_withlen((char*)buff, buff_len);
        }

        // repeat
        // response when received something
        // printf("send m\n");
        uint8_t* msg = new uint8_t[2]; // 1st byte: '~' represent "ACK", 2nd byte: r
        msg[0] = 'm';
        send_response(msg, 1);
    }       
}

string tcp_server::get_stream_cipher(){
    string IV = MAC + to_string(Nonce);
    string tmp_cipher = IV + TK;
    char tmp_2_cipher[17];
    tmp_2_cipher[16]='\0';
    strncpy(tmp_2_cipher, tmp_cipher.c_str(), 16);
    string stream_cipher = tmp_2_cipher;
    Nonce++;    
    return stream_cipher;
}

string tcp_server::get_plain_text(string cipher_text, int len){
    string final_plain = "";
    // int length = cipher_text.length()-1; // the final byte is r.
    int length = len -1; // the final byte is r.
    int pointer = 0;
    // printf("pointer: %d      length: %d\n", pointer, length);
    while(pointer < length){
        string stream_cipher = get_stream_cipher();
        string plain_block;
        string plain_block_tmp;
        plain_block = cipher_text.substr(pointer, 16);            
        // EOR between plain_block and stream_cipher
        string cipher_block = "";
        for(int i = 0 ; i < 16; i++){
            cipher_block = stream_cipher[i]^plain_block[i];
            final_plain += cipher_block;            
        }        
        pointer += 16;
    }
    return final_plain;
}

bool tcp_server::send_response(uint8_t* message, int message_len) // message_len does not include r.
{
    // r is added at the end of message
    message[message_len] = this->r;
    message_len ++;
    
    int send_len = 0;
    char str_header[HEADER_LEN] = {0};

    if ((int)(log10(message_len)/log10(256)) + 1 > HEADER_LEN)
    {
        printf("message size is too big\n");
        return false;
    }   

    // the size of str_header is count
    send_len = message_len;
    for (int count = 0; count < HEADER_LEN; count++)
    {   
        str_header[count] = send_len % 256;
        send_len = send_len / 256;
    }   

    // send the data length first
    send_len = send(connect_fd, str_header, HEADER_LEN, 0); 
    if (send_len < 0)
    {   
        printf("send message error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }
    while (message_len > 0)
    {
        send_len = send(connect_fd, message, message_len > MAXLEN? MAXLEN : message_len, 0);
        if (send_len < 0)
        {
            printf("send message error: %s(errno: %d)\n", strerror(errno), errno);
            return false;
        }
        message = message + send_len;
        message_len = message_len - send_len;
    }

    return true;
}

void tcp_server::output_hex_string(const char* str){
    for (int count = 0; count < strlen(str); count++){
        printf("%02x", (unsigned char)str[count]);
    }
    printf("\n");    
}

void tcp_server::output_hex_string_withlen(const char* str, int len){
    for (int count = 0; count < len; count++){
        printf("%02x", (unsigned char)str[count]);
    }
    printf("\n");    
}
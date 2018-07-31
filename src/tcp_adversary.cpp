#include <iostream>

#include "tcp_adversary.h"
#include "tcp_client.h"
#include "attacker.h"

#define MAXLEN 4096
#define HEADER_LEN 4

using namespace std;

tcp_adversary::tcp_adversary(string str_ap_ip, uint16_t port_ap, uint16_t port_adver)
{
    this->str_ap_ip = str_ap_ip;
    this->port_adver = port_adver;
    this->port_ap = port_ap;
    this->r = 0;
    this->isMsg4 = false;
    this->isMsg4Arrived = false;
    this->isMsg4ArrivedAgain = false;
}

bool tcp_adversary::start_adversary()
{
    // initialize
    socket_client = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_client < 0)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }
    memset(&adversary_addr, 0, sizeof(adversary_addr));
    adversary_addr.sin_family = AF_INET;
    adversary_addr.sin_addr.s_addr = htonl(INADDR_ANY);    // get ip address automatically
    adversary_addr.sin_port = htons(port_adver);          // set port
    
    // bind the locaANONCE_LENl address to the socket
    if (bind(socket_client, (struct sockaddr*)&adversary_addr, sizeof(adversary_addr)) < 0)
    {
        printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }

    // begin listen if there is a connection from client
    if (listen(socket_client, 1024) < 0)
    {
        printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }
    
    client.establish_connection(str_ap_ip.c_str(), port_ap);

    printf("====I am Adversary, I am waiting for client's rquest====\n");
    return true;

}

void tcp_adversary::start_listening()
{
    int data_len = 0;
    uint8_t *buff = NULL;
    uint8_t *buff_resp = NULL;
    unsigned int clientaddr_len = 0;
    while(true)
    {
        clientaddr_len = sizeof(client_addr);
        connect_fd_client = accept(socket_client, (struct sockaddr*)&client_addr, &clientaddr_len);
        if (connect_fd_client < 0)
        {
            printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
            continue;
        }

        while (true)
        {
            this->isMsg4 = false;
            data_len = recv_message(buff);
            if (data_len == -1)
            {
                break;
            }
            // printf("1...recv message from client\n");

            data_process(buff, data_len);

            if (buff != NULL)
            {
                delete[] buff;
                buff = NULL;
            }
            // printf("2...send message to AP\n");

            if (!this->isMsg4)
            {
                int response_len = client.wait_for_response(buff_resp);
                // printf("3...recv message from AP\n");

                send_response(connect_fd_client, buff_resp, response_len);
                if (buff_resp != NULL)
                {   
                    delete[] buff_resp;
                    buff_resp = NULL;
                }   
                // printf("4...send message to client\n");
            }
        }
        close(connect_fd_client);
    }
    close(socket_client);
}


int tcp_adversary::recv_message(uint8_t* &buff)
{
    int recv_len = 0;
    int data_len = 0;
    uint8_t buff_header[HEADER_LEN] = {0};

    recv_len = recv(connect_fd_client, buff_header, HEADER_LEN, 0); 

    if (recv_len <= 0)  // the connection is disconnected by client
    {   
        return -1; 
    }   
    for (int count = HEADER_LEN - 1; count >= 0; count --) 
    {   
        data_len = data_len*256 + buff_header[count];
    }   
    buff = new uint8_t[data_len + 1]; 
    memset(buff, 0, sizeof(buff));

    recv_len = 0;
    while (true)
    {   
        if (recv_len >= data_len)
        {
            break;
        }
        recv_len = recv_len + recv(connect_fd_client, buff+recv_len, data_len, 0); 
    }   
    return recv_len;
}

void tcp_adversary::data_process(uint8_t* buff, int buff_len)
{
    if (buff_len == 2)
    {
        if (buff[0] == '~') // this is a ack message
        {
            this->r = buff[1];
            if (this->r == 2)   // this is Msg4(r+1, ACK) from client
            {
                this->isMsg4 = true;
                this->isMsg4Arrived = true;
                // printf("Msg4(r+1)\n");
            }
            else if (this->r == 3)  // this is Msg4(r+2, ACK) from client
            {
                this->isMsg4ArrivedAgain = true;
                // printf("Msg4(r+2)\n");
            }
        }
    }

    if (buff[0] != '~') // this is not ack message (data message)
    {
        int data_len = buff_len - 1;
        if (this->isMsg4Arrived && !(this->isMsg4ArrivedAgain))
        {
            // first part message
            int index = 0;
            int count = 0;
            while (index < data_len)
            {
                count = 0;
                string str_message = "";
                while (count < 16 && index < data_len)
                {
                    str_message += buff[index];
                    count++;
                    index++;
                }
                vec_mesg_before.push_back(str_message);
            }
        }
        else if (this->isMsg4Arrived && this->isMsg4ArrivedAgain)
        {
            // second part message
            int index = 0;
            int count = 0;
            while (index < data_len)
            {
                count = 0;
                string str_message = "";
                while (count < 16 && index < data_len)
                {
                    str_message += buff[index];
                    count++;
                    index++;
                }
                vec_mesg_after.push_back(str_message);
            }
            if (vec_mesg_after.size() >= vec_mesg_before.size())
            {
                this->isMsg4Arrived = false;
                this->isMsg4ArrivedAgain = false;

                printf("intercepted %ld pairs of secret messages: \n", vec_mesg_before.size());
                for (int i = 0; i < vec_mesg_before.size(); i++)
                {
                    printf("message %d:\n", i);
                    for (int j = 0; j < vec_mesg_before[i].size(); j++)
                    {
                        printf("%02x", (unsigned char)vec_mesg_before[i][j]);
                    }
                    printf("\n");
                }
                printf("\n");
                for (int i = 0; i < vec_mesg_after.size(); i++)
                {
                    printf("message %d: \n", i + (int)vec_mesg_before.size());
                    for (int j = 0; j < vec_mesg_after[i].size(); j++)
                    {
                        printf("%02x", (unsigned char)vec_mesg_after[i][j]);
                    }
                    printf("\n");
                }
                printf("\n");


                Attacker myAttacker;
                myAttacker.get_directory();
                int size = vec_mesg_before.size() < vec_mesg_after.size()? vec_mesg_before.size():vec_mesg_after.size();

                printf("Get %d pair of message\n", size);
                for (int index = 0; index < size; index++)
                {
                    myAttacker.get_plainText(vec_mesg_before[index], vec_mesg_after[index]);
                    printf("For pair %d, there are %ld possible plain text:\n", index, myAttacker.vec_plainText.size()/2);
                    for (int i = 0; i < myAttacker.vec_plainText.size(); i = i+2)
                    {
                        cout << "plainText 1: " << myAttacker.vec_plainText[i] << endl;
                        printf("key: ");
                        for (int j = 0; j < myAttacker.vec_key[i].size(); j++)
                        {
                            printf("%02x", (unsigned char)myAttacker.vec_key[i][j]);
                        }
                        printf("\n");
                        cout << "plainText 2: " << myAttacker.vec_plainText[i+1] << endl;
                        printf("key: ");
                        for (int j = 0; j < myAttacker.vec_key[i+1].size(); j++)
                        {
                            printf("%02x", (unsigned char)myAttacker.vec_key[i+1][j]);
                        }
                        printf("\n\n");
                    }
                    printf("\n");
                }

            }
        }
    }

    if (!isMsg4)
    {
        client.send_message((char*)buff, buff_len);
    }
}

bool tcp_adversary::send_response(int connect_fd_resp, uint8_t* message, int message_len)
{
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
    send_len = send(connect_fd_resp, str_header, HEADER_LEN, 0); 
    if (send_len < 0)
    {   
        printf("send message error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }   
    while (message_len > 0)
    {
        send_len = send(connect_fd_resp, message, message_len > MAXLEN? MAXLEN : message_len, 0);
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


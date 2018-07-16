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
}

tcp_server::tcp_server(uint16_t port)
{
    r = 0;
    state = 0;
    this->port = port;
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
    printf("lengh of data_length: %d\n", recv_len);
    for (int count = HEADER_LEN - 1; count >= 0; count --)
    {
        data_len = data_len*256 + buff_header[count];
    }
    buff = new uint8_t[data_len + 1];
    memset(buff, 0, sizeof(buff));

    printf("data_len: %d\n", data_len);
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

    printf("recv_len: %d\n", recv_len);
    printf("recv_data: %s\n", buff);
    printf("address: %p\n", buff);
    return recv_len;
}

void tcp_server::data_process(uint8_t* buff, int buff_len)
{
    string str_buff = (char*)buff;

    if (buff_len < 0)
    {
        return;
    }

    if (str_buff.compare("Authentication_Request") == 0)
    {

        // get request of client, send ANonce and r to client
        this->r = 1;
        this->state = 1;
        uint8_t buff_ANonce[ANONCE_LEN];
        rander myRander;
        
        // 2. generate ANonce
        printf("Generate ANonce: ");
        myRander.get_random(buff_ANonce, ANONCE_LEN);
        for(int count = 0; count < ANONCE_LEN; count++)
        {
            printf("%02x", buff_ANonce[count]);
        }
        printf("\n");
        


        send_response(buff_ANonce, ANONCE_LEN);
    }
    puts("----------");
}

bool tcp_server::send_response(uint8_t* message, int message_len)
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


#include "tcp_client.h"

#define MAXLEN 4096
#define HEADER_LEN 4

tcp_client::tcp_client()
{
}

bool tcp_client::establish_connection(const char* addr, uint16_t port)
{
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0)
    {
        printf("inet_pton error for %s\n", addr);
        return false;
    }

    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }
}

void tcp_client::end_connection()
{
    close(socket_fd);
}

bool tcp_client::send_message(const char* message, int length)
{
    int send_len = 0;
    char str_header[HEADER_LEN] = {0};

    if ((int)(log10(length)/log10(256)) + 1 > HEADER_LEN)
    {
        printf("message size is too big\n");
        return false;
    }

    // the size of str_header is count
    send_len = length;
    for (int count = 0; count < HEADER_LEN; count++)
    {
        str_header[count] = send_len % 256;
        send_len = send_len / 256;
    }

    // send the data length first
    send_len = send(socket_fd, str_header, HEADER_LEN, 0);
    if (send_len < 0)
    {
        printf("send message error: %s(errno: %d)\n", strerror(errno), errno);
        return false;
    }

    while (length > 0)
    {
        send_len = send(socket_fd, message, length > MAXLEN? MAXLEN : length, 0);
        if (send_len < 0)
        {
            printf("send message error: %s(errno: %d)\n", strerror(errno), errno);
            return false;
        }
        message = message + send_len;
        length = length - send_len;
    }

    return true;
}

int tcp_client::wait_for_response(uint8_t* &buff)
{
    int recv_len = 0;
    int data_len = 0;
    uint8_t buff_header[HEADER_LEN] = {0};

    // recv data length first
    recv_len = recv(socket_fd, buff_header, HEADER_LEN, 0);

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

    // recv real data
    recv_len = 0;
    while (true)
    {   
        if (recv_len >= data_len)
        {
            break;
        }
        recv_len = recv_len + recv(socket_fd, buff+recv_len, data_len, 0); 
    }
    return recv_len;
}

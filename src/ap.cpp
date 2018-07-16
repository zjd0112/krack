#include <iostream>

#include "tcp_server.h"

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
		printf("Usage: ./AP MasterKey PORT\n");
		printf("Exampele: ./AP 1111 1234\n");
		return 0;
    }


    uint16_t port;
    
    port = (uint16_t)atoi(argv[2]);

    tcp_server server(port);
    server.str_masterKey = argv[1];

    server.start_server();
    server.start_listening();

    return 0;
}

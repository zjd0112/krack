#include <iostream>

#include "tcp_adversary.h"

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
		printf("Usage: ./Adversary AP_IP AP_PORT ADVERSARY_PORT\n");
		printf("Exampele: ./Adversary 127.0.0.1 1234 4567\n");
		return 0;
    }

    uint16_t port_ap = 0;
    uint16_t port_adver = 0;
    string str_ap_ip = "";
    
    str_ap_ip = argv[1];
    port_ap = (uint16_t)atoi(argv[2]);
    port_adver = (uint16_t)atoi(argv[3]);

    tcp_adversary adver(str_ap_ip, port_ap, port_adver);

    adver.start_adversary();
    adver.start_listening();

    return 0;
}

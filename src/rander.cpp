#include "rander.h"

void rander::get_random(unsigned char* buff_random, unsigned int len)
{
    srand((unsigned)time(NULL)); 
    for(int count = 0; count < len; count++ )
    {
        buff_random[count] = (unsigned char)(rand()%256);
    }
}

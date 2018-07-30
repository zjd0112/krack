#include <iostream>
#include <string>

#include "attacker.h"

using namespace std;

int main()
{
    string str_path = "temp.txt";
    Attacker myAttacker(str_path);
    myAttacker.get_directory();

    string str_xor = "";
    string str1 = "POSTGETHTTPINPUT";
    string str2 = "OUTPUTGETPOSTGET";
    for (int i = 0; i < 16; i++)
    {
        str_xor += str1[i]^str2[i];
    }
    myAttacker.get_plainText(str_xor);
    return 0;
}

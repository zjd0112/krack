/**************************************************************************

Author: zjd

Date:2018-07-28

Description: Get plain text base on XOR data

**************************************************************************/
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;

class Attacker {
    
    private:
        string str_metaData[5];
        string str_directory_path;
        vector <string> vec_words;
        multimap <string, string> map_words;

        void place_metaData(int nowPos, int maxLen, int stringLen, int comb_words[]);
        void string_xor(string str1, string str2, string& str_res);


    public:
        Attacker();
        Attacker(string str_directory_path);
        void get_plainText(string XOR_text);
        void get_plainText(string str1, string str2);
        void get_directory();
};

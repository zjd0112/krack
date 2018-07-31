/**************************************************************************

Author: zjd

Date:2018-07-28

Description: Get plain text base on XOR data

**************************************************************************/

#include <iostream>
#include <string>
#include <map>

#include "attacker.h"

#define METADATA_NUM 5
#define MAX_METADATA_NUM 6
#define MAX_STRING_LEN 16
#define BLOCK_XOR_SIZE 16

using namespace std;


Attacker::Attacker()
{
	this->str_metaData[0] = "POST";
    this->str_metaData[1] = "GET";
    this->str_metaData[2] = "HTTP";
    this->str_metaData[3] = "INPUT";
    this->str_metaData[4] = "OUTPUT";
}

Attacker::Attacker(string str_directory_path)
{
    this->str_metaData[0] = "POST";
    this->str_metaData[1] = "GET";
    this->str_metaData[2] = "HTTP";
    this->str_metaData[3] = "INPUT";
    this->str_metaData[4] = "OUTPUT";
    this->str_directory_path = str_directory_path;
}


void Attacker::place_metaData(int nowPos, int maxLen, int stringLen, int comb_words[])
{
    // get combination of words
    if (nowPos == maxLen && stringLen <= MAX_STRING_LEN)
    {
        string str_comb = "";
        for (int index = 0; index < nowPos; index++)
        {
            str_comb += str_metaData[comb_words[index]];
        }
        vec_words.push_back(str_comb);
        return;
    }
    else if (nowPos > maxLen || stringLen > MAX_STRING_LEN)
    {
        return;
    }
    else
    {
        for (int meta_index = 0; meta_index < METADATA_NUM; meta_index++)
        {
            comb_words[nowPos] = meta_index;
            place_metaData(nowPos+1, maxLen, stringLen + str_metaData[meta_index].size(), comb_words);
            comb_words[nowPos] = -1;
        }
    }
}

void Attacker::string_xor(string str1, string str2, string& str_res)
{
    int str1_size = str1.size();
    int str2_size = str2.size();
    int str_size_min = 0;
    int str_size_max = 0;
    bool str1_bigger = false;

    if (str1_size < str2_size)
    {
        str1_bigger = false;
        str_size_min = str1_size;
        str_size_max = str2_size;
    }
    else
    {
        str1_bigger = true;
        str_size_min = str2_size;
        str_size_max = str1_size;
    }

    for (int str_index = 0; str_index < str_size_min; str_index++)
    {
        str_res += str1[str_index] ^ str2[str_index];
    }

    if (str1_bigger)
    {
        int str_index = str_size_min;
        while(str_index < str_size_max)
        {
            str_res += str1[str_index];
            str_index++;
        }
    }
    else
    {
        int str_index = str_size_min;
        while(str_index < str_size_max)
        {
            str_res += str2[str_index];
            str_index++;
        }
    }

    // if the xor data size is less than 128, then add "0"
    int str_index = str_size_max;
    while (str_index < BLOCK_XOR_SIZE)
    {
        str_res += (char)0;
        str_index++;
    }
    return;
}


void Attacker::get_directory()
{
    int comb_words[MAX_METADATA_NUM];

    // produce different combination of different words
    for (int len = 1; len <= 6; len++)
    {
        place_metaData(0, len, 0, comb_words);
    }
    
    unsigned long int vec_size = vec_words.size();
    for (unsigned long int index_vec_i = 0; index_vec_i < vec_size; index_vec_i++)
    {
        for (unsigned long int index_vec_j = 0; index_vec_j < vec_size; index_vec_j++)
        {
            string str_xor = "";
            string_xor(vec_words[index_vec_i], vec_words[index_vec_j], str_xor);
            map_words.insert(pair<string, string>(str_xor, vec_words[index_vec_i]));
            map_words.insert(pair<string, string>(str_xor, vec_words[index_vec_j]));
        }
    }
}


void Attacker::get_plainText(string str_xor)
{
    multimap<string, string>::iterator map_itera;
    int num = map_words.count(str_xor);
    // cout << num << endl;
    
    map_itera = map_words.find(str_xor);
    for (int index = 0; index < num; index++)
    {
        // cout << (*map_itera).second << endl;
        vec_plainText.push_back((*map_itera).second);
        map_itera++;
    }
}

void Attacker::get_plainText(string str1, string str2)
{
    string str_xor = "";
    int index = 0;
    int str1_size = str1.size();
    int str2_size = str2.size();
    int min_size = str1_size < str2_size? str1_size:str2_size;
    int max_size = str1_size < str2_size? str2_size:str1_size;
    bool str1Bigger = str1_size < str2_size? false:true;

    for (index = 0; index < min_size; index++)
    {
        str_xor += str1[index] ^ str2[index];
    }
    if (str1Bigger)
    {
        while (index < max_size)
        {
            str_xor += str1[index];
        }
    }
    else
    {
        while (index < max_size)
        {
            str_xor += str2[index];
        }
    }

    while (str_xor.size() < BLOCK_XOR_SIZE)
    {
        str_xor += (char)0;
    }

    vec_plainText.clear();
    vec_key.clear();
    get_plainText(str_xor);
    
    int size = vec_plainText.size();
    index = 0;
    while (index < size)
    {
        string str_M1 = vec_plainText[index];
        string str_M2 = vec_plainText[index + 1];
        string str_key1 = "";
        string str_key2 = "";

        int M1_size = str_M1.size();
        int M2_size = str_M2.size();

        for (int i = 0; i < M1_size; i++)
        {
            str_key1 += str_M1[i] ^ str1[i];
        }
        for (int i = 0; i < M2_size; i++)
        {
            str_key2 += str_M2[i] ^ str2[i];
        }

        while (str_key1.size() < BLOCK_XOR_SIZE)
        {
            str_key1 += (char)0;
        }
        while (str_key2.size() < BLOCK_XOR_SIZE)
        {
            str_key2 += (char)0;
        }

        vec_key.push_back(str_key1);
        vec_key.push_back(str_key2);

        index = index + 2;
    }
}

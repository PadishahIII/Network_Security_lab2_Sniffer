#include <stdio.h>
#include <string.h>
#include <iostream>
using namespace std;
void printIPAddr(u_char *start)
{
    string str = "";
    for (int j = 0; j < 4; j++)
    {
        str += to_string((unsigned int)start[j]);
        if (j != 4 - 1)
            str += ".";
    }
    cout << str;
}
int main()
{
    unsigned int i = 0x11223344;
    unsigned char c = 0x01;
    // cout << std::hex << i;
    // printf("%02x", i);
    i = 0xac17eac1;
    unsigned int j = 0x284de2fa;
    printIPAddr((u_char *)&i);
    cout << endl;
    printIPAddr((u_char *)&j);
    unsigned char *byte = (unsigned char *)&i;
}
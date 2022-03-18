#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
using namespace std;

void handle_ethernet_pkt(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
int main(int argc, char **argv)
{
    int res;
    pcap_if_t *NetworkDevices;
    pcap_t *handle;
    pcap_if_t *device;
    char errorWin[PCAP_ERRBUF_SIZE];
    char DeviceName[100][1000];

    if ((res = pcap_findalldevs(&NetworkDevices, errorWin)) < 0)
    {
        perror("pcap_findalldevs");
        exit(-1);
    }
    int i = 0;
    for (device = NetworkDevices; device && i < 10; device = device->next, i++)
    {
        cout << "*************************" << endl;
        cout << "Number:" << i << endl;
        cout << device->name << endl;
        if (device->description)
            cout << device->description << endl;
        sprintf(DeviceName[i], "%s", device->name);
        cout << "*************************" << endl;
    }
    int devicenum = -1;
    while (true)
    {
        cout << "Choose Device Number:(0-" << i - 1 << ")" << endl;
        scanf("%d", &devicenum);
        if (devicenum < 0 || devicenum > i - 1)
        {
            cout << "Please Input a vaild device number!" << endl;
            continue;
        }
        cout << "Device:" << DeviceName[devicenum] << endl;
        cout << "Begin sniffer..." << endl;
        break;
    }
    for (device = NetworkDevices, i = 0; i < devicenum; device = device->next, i++)
        ;
    if ((handle = pcap_open_live(DeviceName[devicenum], BUFSIZ, 1, 1000, errorWin)) == NULL)
    {
        perror("pcap_open_live");
        pcap_freealldevs(NetworkDevices);
        exit(-1);
    }
    pcap_loop(handle, -1, handle_ethernet_pkt, NULL);
    pcap_freealldevs(NetworkDevices);
    pcap_close(handle);
    return 0;
}
void handle_ethernet_pkt(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
    static int pktnum = 0;
    pktnum++;
    cout << "Pkt Number:" << pktnum << endl;
    int pkt_length = packet_header->len;
    cout << "Pkt Length:" << pkt_length << endl;
    int end = 0;
    int line_length = 16; //每行显示的字符数
    char DataOut[line_length];
    // if (pkt_length > 0)
    //{
    //     for (int i = 0; i < pkt_length; i++)
    //     {
    //         printf("%02X", packet_content[i]);
    //         if (isgraph(packet_content[i])) //可打印字符
    //         {
    //             DataOut[end] = packet_content[i];
    //         }
    //         else if (packet_content[i] == ' ')
    //         {
    //             DataOut[end] = packet_content[i];
    //         }
    //         else
    //         {
    //             DataOut[end] = '.';
    //         }
    //         end++;
    //         if (i % line_length == (line_length - 1))
    //         {
    //             DataOut[end] = '\0';
    //             cout << "         " << DataOut << endl;
    //             end = 0;
    //         }
    //     }
    //     if (end > 0)
    //     {
    //         for (int k = end * 2; k < line_length * 2; k++)
    //             cout << " ";
    //         DataOut[end] = 0;
    //         cout << "         " << DataOut << endl;
    //     }
    // }
}
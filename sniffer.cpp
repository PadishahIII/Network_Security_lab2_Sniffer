#include <fstream>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
using namespace std;

#define ETHERNET_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct ethernet
{
    u_char dst_mac_addr[ETHERNET_ADDR_LEN]; //目的主机MAC地址
    u_char src_mac_addr[ETHERNET_ADDR_LEN];
    u_short pro_type; //协议类型
};
struct ip
{
    u_char version_hlen; //版本号+头部长度 1字节
    u_char service;      //服务类型
    u_short total_len;   //总长度
    u_short id;          //标识
    u_short flag_shift;  //标志+片偏移
    u_char ttl;
    u_char protocol; //协议
    u_short checksum;
    u_char src_ip_addr[IP_ADDR_LEN];
    u_char dst_ip_addr[IP_ADDR_LEN];
};
struct tcp
{
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack;
    u_char headlen; //高四位是数据偏移即头长度，后4位保留
    u_char flag;    //高2bit为保留，低6bit为标志
    u_short win;    //窗口大小
    u_short checksum;
    u_short urp; //紧急指针(urgent pointer)
};
struct udp
{
    u_short src_port;
    u_short dst_port;
    u_short len; //总长度
    u_short checksum;
};

void printMacAddr(u_char *, int size, FILE *);
void printIPAddr(u_char *, FILE *);
void convert(u_char *, int); //转换字节序
void handle_ethernet_pkt(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);

bool all_opt = false;
bool out_opt = false;
char *filename = NULL;
FILE *file = stdout;
// ofstream *of_ptr = NULL;
int main(int argc, char **argv)
{
    int opt;
    const char *optstring = "ao:h";
    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
        if (opt == 'a') //打印数据包内容
        {
            all_opt = true;
        }
        else if (opt == 'o')
        {
            out_opt = true;
            filename = (char *)malloc(strlen(optarg) + 2);
            memset(filename, 0, strlen(optarg) + 2);
            memccpy(filename, optarg, 0, strlen(optarg) + 1);
            file = fopen(filename, "w");
            if (!file)
            {
                perror("fopen");
                exit(-1);
            }
        }
        else if (opt == 'h')
        {
            cout << "Usage:\n\t-a    print raw data\n\t-o    output to a file\n";
            exit(0);
        }
    }

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
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    char bpf_filter_string[] = "ip";
    struct bpf_program bpf_filter;
    string input;
    getchar();
    while (true)
    {
        cout << "Input filter rule:(default:\"ip\")" << endl;
        getline(cin, input);
        if (input.empty())
        {
            pcap_compile(handle, &bpf_filter, bpf_filter_string, 0, net_ip);
            break;
        }
        else
        {
            if (pcap_compile(handle, &bpf_filter, input.c_str(), 0, net_ip) < 0)
            {
                cout << "Invaild filter rule!" << '\"' << input << '\"' << endl;
                continue;
            }
            else
            {
                break;
            }
        }
    }
    pcap_setfilter(handle, &bpf_filter);
    if (!all_opt)
        cout
            << "DST MAC ADDRESS  "
            << "SRC MAC ADDRESS "
            << "DST IP ADDRESS  "
            << "SRC IP ADDRESS  "
            << "PROTOCOL"
            << "  DST PORT  "
            << "  SRC PORT " << endl;
    pcap_loop(handle, -1, handle_ethernet_pkt, NULL);
    pcap_freealldevs(NetworkDevices);
    pcap_close(handle);
    return 0;
}
void handle_ethernet_pkt(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
    static int pktnum = 0;
    pktnum++;
    int pkt_length = packet_header->len;
    int end = 0;
    int line_length = 16; //每行显示的字符数
    char DataOut[line_length];

    if (all_opt)
    {
        cout << "Pkt Number:" << pktnum << endl;
        cout << "Pkt Length:" << pkt_length << endl;
        if (pkt_length > 0)
        {
            for (int i = 0; i < pkt_length; i++)
            {
                printf("%02X ", packet_content[i]);
                if (isgraph(packet_content[i])) //可打印字符
                {
                    DataOut[end] = packet_content[i];
                }
                else if (packet_content[i] == ' ')
                {
                    DataOut[end] = packet_content[i];
                }
                else
                {
                    DataOut[end] = '.';
                }
                end++;
                if (i % line_length == (line_length - 1))
                {
                    DataOut[end] = '\0';
                    cout << "         " << DataOut << endl;
                    end = 0;
                }
            }
            if (end > 0)
            {
                for (int k = end * 2; k < line_length * 2; k++)
                    cout << " ";
                DataOut[end] = 0;
                cout << "         " << DataOut << endl;
            }
        } // if pkt_length>0
    }     // if all_opt
    // if (out_opt && (filename != NULL) && (file != NULL))
    if (out_opt || !all_opt)
    {
        struct ethernet *ethernet = (struct ethernet *)packet_content;
        // cout << ethernet->dst_mac_addr << "  " << (char *)ethernet->src_mac_addr << "   ";
        if (ethernet->pro_type == 0x0008) // ipv4
        {
            printMacAddr(ethernet->dst_mac_addr, ETHERNET_ADDR_LEN, file);
            fprintf(file, "   ");
            printMacAddr(ethernet->src_mac_addr, ETHERNET_ADDR_LEN, file);
            fprintf(file, "    ");
            struct ip *ip = (struct ip *)(ethernet + 1);
            printIPAddr(ip->dst_ip_addr, file);
            fprintf(file, "     ");
            printIPAddr(ip->src_ip_addr, file);
            fprintf(file, "     ");

            if (ip->protocol == 0x06) // TCP
            {
                fprintf(file, "TCP      ");
                struct tcp *tcp = (struct tcp *)(ip + 1);
                convert((u_char *)&tcp->dst_port, sizeof(u_short));
                convert((u_char *)&tcp->src_port, sizeof(u_short));
                fprintf(file, "%u          %u\n", tcp->dst_port, tcp->src_port);
            }
            else if (ip->protocol == 0x11) // UDP
            {
                fprintf(file, "UDP       ");
                struct udp *udp = (struct udp *)(ip + 1);
                convert((u_char *)&udp->src_port, sizeof(u_short));
                convert((u_char *)&udp->src_port, sizeof(u_short));
                fprintf(file, "%u          %u\n", udp->dst_port, udp->src_port);
            }
        }
    }
}
void printMacAddr(u_char *start, int size, FILE *out)
{
    fprintf(file, "0x");
    for (int i = 0; i < size; i++)
        fprintf(out, "%02x", start[i]);
}
void printIPAddr(u_char *start, FILE *out)
{
    string str = "";
    for (int j = 0; j < IP_ADDR_LEN; j++)
    {
        str += to_string((unsigned int)start[j]);
        if (j != IP_ADDR_LEN - 1)
            str += ".";
    }
    // cout << str;
    fprintf(out, "%s", str.c_str());
}
void convert(u_char *start, int size)
{
    u_char tmp;
    for (int i = 0; i <= (size - 1) / 2; i++)
    {
        tmp = start[i];
        start[i] = start[size - i - 1];
        start[size - i - 1] = tmp;
    }
}
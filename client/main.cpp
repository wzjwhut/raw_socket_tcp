#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include "simple_tcp.h"
#include "routing_table.h"


#include <QCoreApplication>

/** iptables -t filter -I OUTPUT -p tcp --dport 11234 --tcp-flags RST RST -j DROP */

void test_raw_socket()
{


    const char* dst = "115.28.94.100";
    const int dst_port = 11234;
    rawtcp_t *tcp;


    if ((tcp = rawtcp_connect(dst, dst_port)) == NULL)
    {
        printf("TCP Connection Failed\n");
        return;
    }
    else
    {
        printf("TCP Connection Successful\n");
    }
    sleep(5);


    int ret = 0;
    char* get_command = "test";
    if ((ret = rawtcp_send(tcp, get_command, strlen(get_command))))
    {
        printf("rawtcp_send error\n");
        goto EXIT;
    }else{
        printf("send ok\n");
    }



    printf("Processing Done!!\n");
EXIT:
    rawtcp_close(tcp);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    test_raw_socket();
    //pause();
    return a.exec();
}

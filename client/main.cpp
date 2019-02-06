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
#include "rawtcp.h"
#include "routing_table.h"

#ifdef BUILD_QT
#include <QCoreApplication>
#endif

#ifdef __cplusplus
#undef NULL
#define NULL nullptr
#endif

/** iptables -t filter -I OUTPUT -p tcp --dport 11234 --tcp-flags RST RST -j DROP
iptables -t filter -I OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP
*/

void test_raw_socket()
{
    const char* dst = "www.baidu.com";
    const int dst_port = 80;

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

    int ret = 0;
    const int recv_buf_len = 8192;
    char* recv_buf = (char*)malloc(recv_buf_len);
    const char* get_command = "GET / HTTP/1.1\r\n"
            "Host: www.baidu.com\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";
    if ((ret = rawtcp_send(tcp, get_command, strlen(get_command))))
    {
        printf("rawtcp_send error\n");
        goto EXIT;
    }else{
        printf("rawtcp_send ok\n");
    }

    while( (ret = rawtcp_recv(tcp, recv_buf, recv_buf_len)) >=0 ){
        if(ret>0){
            recv_buf[ret] = 0;
            printf("recved\n%s\n", recv_buf);
        }

        usleep(100*1000);
    }
    printf("socket disconnected\n");
EXIT:
    rawtcp_close(tcp);
    free(recv_buf);
}

int main(int argc, char *argv[])
{
#ifdef BUILD_QT
    QCoreApplication a(argc, argv);
#endif
    test_raw_socket();
    pause();

#ifdef BUILD_QT
    return a.exec();
#endif
}

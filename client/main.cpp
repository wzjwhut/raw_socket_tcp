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
#include "tcp_handler.h"
#include "routing_table.h"


#include <QCoreApplication>

/** iptables -t filter -I OUTPUT -p tcp --dport 11234 --tcp-flags RST RST -j DROP */

void test_raw_socket()
{
    int send_sock_fd = -1, recv_sock_fd = -1;
    struct sockaddr_in src_addr, dst_addr;
    struct hostent *host_details = NULL;
    packet_t packet;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    char *data = NULL;
    const char* dst = "115.28.94.100";
    const int dst_port = 11234;
    const int src_port = random();
    if (NULL == (host_details = gethostbyname(dst)))
    {
        printf("ERROR: Failed to resolve hostname: %s\n", dst);
        return;
    }

    memset(&src_addr, 0, sizeof(struct sockaddr_in));
    memset(&dst_addr, 0, sizeof(struct sockaddr_in));

    uint32_t src_address = getLocalIPAddress(
            ((struct in_addr *) host_details->h_addr)->s_addr);

    printf("local addr: %u\n", src_address);
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(src_port);
    src_addr.sin_addr = *(struct in_addr *) &src_address;

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    dst_addr.sin_addr = *((struct in_addr *) host_details->h_addr);

    send_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (send_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        return;
    }

    recv_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (recv_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        return;
    }

    if (bind(recv_sock_fd, (const struct sockaddr *) &src_addr,
            sizeof(struct sockaddr_in)) < 0)
    {
        printf("Error: Unable to bind the receiving socket: %s\n",
                strerror(errno));
        return;
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;

    if (setsockopt(recv_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        return;
    }

    char psrc_addr[256] = { 0 };
    char pdst_addr[256] = { 0 };
    printf("Src Address: %s Destination Address: %s\n",
            inet_ntop(AF_INET, &src_addr.sin_addr.s_addr, psrc_addr, 256),
            inet_ntop(AF_INET, &dst_addr.sin_addr.s_addr, pdst_addr, 256));

    if (connect_tcp(send_sock_fd, recv_sock_fd, &dst_addr, &src_addr) < 0)
    {
        printf("TCP Connection Failed\n");
        goto EXIT;
    }
    else
    {
        printf("TCP Connection Successful\n");
    }

    {
        int ret = 0;
        char* get_command = "test";
        if ((ret = send_data(get_command, strlen(get_command))) < 0
                || ret != strlen(get_command))
        {
            printf("Failed to send get_request!!\n");
            goto EXIT;
        }else{
            printf("send ok\n");
        }
    }




    printf("Processing Done!!\n");
EXIT:
    close_tcp();
    close(send_sock_fd);
    close(recv_sock_fd);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    test_raw_socket();
    return a.exec();
}

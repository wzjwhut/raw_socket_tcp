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
#define PCKT_LEN 8192

struct ipheader {

    unsigned char      iph_ihl:5, /* Little-endian */
        iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flags;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

/* Structure of a TCP header */

struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    // unsigned char tcph_flags;
    unsigned int
    tcp_res1:4,      /*little-endian*/
        tcph_hlen:4,     /*length of tcp header in 32-bit words*/
        tcph_fin:1,      /*Finish flag "fin"*/
        tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
        tcph_rst:1,      /*Reset flag */
        tcph_psh:1,      /*Push, sends data to the application*/
        tcph_ack:1,      /*acknowledge*/
        tcph_urg:1,      /*urgent pointer*/
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};


static const char hexdig[] = "0123456789abcdef";
static void log_hex(const char* tag, unsigned char* data, int len){
    char msg[50], *ptr;
    int i;
    ptr = msg;

    printf("%s\r\n", tag);
    for(i=0; i<len; i++) {
        *ptr++ = hexdig[0x0f & (data[i] >> 4)];
        *ptr++ = hexdig[0x0f & data[i]];
        if ((i & 0x0f) == 0x0f) {
            *ptr = '\0';
            ptr = msg;
            printf("%s\r\n", msg);
        } else {
            *ptr++ = ' ';
        }
    }
    if (i & 0x0f) {
        *ptr = '\0';
        printf("%s\r\n", msg);
    }
}


// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC

static unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for(sum=0; len>0; len--)
    {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void test_send()
{
    printf("test send\n");
    const char* src_ip = "127.0.0.1";
    const char* src_port = "10000";
    const char* dst_ip = "115.28.94.100";
    const char* dst_port = "80";
    int sd;
    // No data, just datagram
    char buffer[PCKT_LEN];
    // The size of the headers
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    memset(buffer, 0, PCKT_LEN);
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd < 0)
    {
        perror("socket() error");
        return;
    }
    else
    {
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
    }
    // The source is redundant, may be used later if needed
    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Source port, can be any, modify as needed
    sin.sin_port = htons(atoi(src_port));
    din.sin_port = htons(atoi(dst_port));
    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr(src_ip);
    din.sin_addr.s_addr = inet_addr(dst_ip);

    if(bind(sd, (struct sockaddr*)&sin, sizeof(sin))){
        perror("bind");
        return;
    }


    // IP structure
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
    ip->iph_ident = htons(54321);
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = 6; // TCP
    ip->iph_chksum = 0; // Done by kernel
    // Source IP, modify as needed, spoofed, we accept through command line argument
    ip->iph_sourceip = inet_addr(src_ip);
    // Destination IP, modify as needed, but here we accept through command line argument
    ip->iph_destip = inet_addr(dst_ip);
    // The TCP structure. The source port, spoofed, we accept through the command line
    tcp->tcph_srcport = htons(atoi(src_port));
    // The destination port, we accept through command line
    tcp->tcph_destport = htons(atoi(dst_ip));
    tcp->tcph_seqnum = htonl(1);
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = 5;
    tcp->tcph_syn = 1;
    tcp->tcph_ack = 0;
    tcp->tcph_win = htons(32767);
    tcp->tcph_chksum = 0; // Done by kernel
    tcp->tcph_urgptr = 0;
    // IP checksum calculation
    ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct ipheader) + sizeof(struct tcpheader)));

    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        return;
    }
    else
    {
        printf("setsockopt() is OK\n");
    }

    log_hex("tcp header", (uint8_t*)buffer, ip->iph_len);

    // sendto() loop, send every 2 second for 50 counts
    unsigned int count;
    for(count = 0; count < 5; count++)
    {
        if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            perror("sendto() error");
            return;
        }
        else
        {
            printf("Count #%u - sendto() is OK\n", count);
        }
        //sleep(2);
    }

    {
        char recv_buf[4096] = "";
        printf("begin receive\n");
        int recv_len = recv(sd,recv_buf,sizeof(recv_buf),0);
        printf("recved: %d\n", recv_len);
        if (recv_len <=0)
        {
            perror("recv error");
        }
    }
    close(sd);

}


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
    src_addr.sin_port = htons((uint16_t) getpid());
    src_addr.sin_addr = *(struct in_addr *) &src_address;

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(HTTP_PORT);
    dst_addr.sin_addr = *((struct in_addr *) host_details->h_addr);

    send_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (send_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        exit(1);
    }

    recv_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (recv_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        exit(1);
    }

    if (bind(recv_sock_fd, (const struct sockaddr *) &src_addr,
            sizeof(struct sockaddr_in)) < 0)
    {
        printf("Error: Unable to bind the receiving socket: %s\n",
                strerror(errno));
        exit(1);
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;

    if (setsockopt(recv_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(1);
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

    printf("Processing Done!!\n");
    EXIT: close_tcp();
    close(send_sock_fd);
    close(recv_sock_fd);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    test_raw_socket();
    return a.exec();
}

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


//#include <QCoreApplication>
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


static void test_recv()
{
    int ret ;
    fd_set read_set;
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd< 0){
        perror("create socket error");
        exit(-1);
    }

//    int one = 1;
//    const int *val = &one;
//    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
//    {
//        perror("setsockopt() error");
//        exit(-1);
//    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(20000);
//    if(bind(sd, (struct sockaddr*)&addr, sizeof(addr))){
//        perror("bind");
//        exit(-1);
//    }

    uint8_t* buffer = (uint8_t*)malloc(ETH_FRAME_LEN);
    while (true)
    {
        FD_ZERO(&read_set);
        FD_SET(sd, &read_set);
        printf("select\n");
        ret = select(sd+1, &read_set, NULL, NULL, NULL);
        printf("select end\n");
        if(ret > 0 && FD_ISSET(sd, &read_set))
        {
            printf("server socket readable\n");
            int len = recv(sd, buffer, ETH_FRAME_LEN, 0);
            printf("server recived: %d \n", len);
            if(len>0){
                log_hex("recv", buffer, len);
            }
        }
    }
}


int main(int argc, char *argv[])
{
    //QCoreApplication a(argc, argv);
    test_recv();
    //return a.exec();
}

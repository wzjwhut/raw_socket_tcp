/*
 * tcp_handler.h
 *
 *  Created on: Dec 8, 2015
 *      Author: Praveen
 */

#ifndef TCP_HANDLER_H_
#define TCP_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "outstream.h"

#define TOTAL_LAYERS  2
#define IP_LAYER_OFFSET  0
#define TCP_LAYER_OFFSET 1
#define PAYLOAD_OFFSET 2
#define CLIENT_PORT 35555
#define HTTP_PORT 80
#define RTAX_MAX 8
#define IP_OFFSET 0
#define TCP_OFFSET 1
#define DATA_OFFSET 2
#define MAX_BUFFER_SIZE 400
#define MAX_CLIENT_SEGMENT_SIZE 1460
#define CLIENT_WINDOW_SIZE 16384
#define WORD_LENGTH 4
#define PACKET_MAX_SIZE 16384
#define MAX_PAYLOAD_LEN (PACKET_MAX_SIZE - sizeof(struct iphdr) - sizeof(struct tcphdr))
#define MAX_CONGESTION_WINDOW_SIZE 1000

typedef enum
{
    SYN_SENT = 1,
    ESTABLISHED = 2,
    FIN_WAIT_1 = 4,
    FIN_WAIT_2 = 8,
    CLOSE_WAIT = 16,
    CLOSING = 32,
    LAST_ACK = 64,
    CLOSED = 128
} tcp_state_t;

typedef struct
{
    uint8_t syn :1;
    uint8_t ack :1;
    uint8_t fin :1;
    uint8_t psh :1;
} tcp_flags_t;

typedef struct
{
    uint8_t option_type;
    uint8_t option_len;
    uint16_t option_value;
} tcp_options_t;

typedef struct
{
    char payload[PACKET_MAX_SIZE];
    char* offset[TOTAL_LAYERS + 1];
    uint16_t payload_len;
} packet_t;


typedef struct
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} pseudo_header;

typedef struct
{
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    int send_fd;
    int recv_fd;
} session_info__t;


typedef struct
{
    session_info__t session_info;
    uint32_t client_next_seq_num;
    uint32_t last_acked_seq_num;
    uint32_t server_next_seq_num;
    uint16_t server_window_size;
    uint16_t client_window_size;
    uint16_t max_segment_size;
    uint16_t cwindow_size;
    uint16_t ssthresh;
    uint8_t syn_retries;
    uint8_t tcp_write_end_closed;
    uint8_t tcp_read_end_closed;
    outstream_t outstream;
    tcp_state_t tcp_current_state;
    int send_fd;
    int recv_fd;
} rawtcp_t;

rawtcp_t* rawtcp_connect(const char* dest_ip, int dst_port);
int rawtcp_send(rawtcp_t* tcp, const char* buffer, size_t buffer_len);
int rawtcp_recv(rawtcp_t* tcp, char* buffer, int buffer_len);
void rawtcp_close(rawtcp_t* tcp);

#ifdef __cplusplus
}
#endif

#endif /* TCP_HANDLER_H_ */

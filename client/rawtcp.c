/*
 * tcp_handler.c
 *
 *  Created on: Dec 8, 2015
 *      Author: Praveen
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include "rawtcp.h"
#include "routing_table.h"


#define STARTING_SEQUENCE 10*10
#define TCP_WORD_LENGTH_WITH_NO_OPTIONS 5
#define HAS_TCP_OPTIONS(ptr) (ptr->doff > TCP_WORD_LENGTH_WITH_NO_OPTIONS)
#define TCP_OPTION_OFFSET(ptr) ((char*)ptr + (TCP_WORD_LENGTH_WITH_NO_OPTIONS * WORD_LENGTH))
#define TCP_OPTION_LENGTH(ptr) ((ptr->doff - TCP_WORD_LENGTH_WITH_NO_OPTIONS) * WORD_LENGTH)
#define END_OF_TCP_OPTION_CHECK(ptr) ((*ptr) == 0)
#define TCP_OPTIONS_LEN(ptr) ((ptr->doff - TCP_WORD_LENGTH_WITH_NO_OPTIONS) * WORD_LENGTH )
#define IS_NO_OPERATION(ptr) ((*ptr) == 1)
#define IS_MSS(ptr) ((*ptr) == 2)
#define OPTION_LENGTH(ptr) (*(ptr+1))
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#define TCP_OPTION_DATA_OFFSET 2

#define IS_DUPLICATE_TCP_SEGMENT(tcph) (ntohl(tcph->seq) < tcp_state->server_next_seq_num)
#define IS_DUPLICATE_ACK(tcph) (tcph->ack && (tcph->ack_seq == tcp_state->last_acked_seq_num) )
#define WRAP_ROUND_BUFFER_SIZE(index) \
		({ __typeof__ (index) _index = (index); \
		 ( _index + 1) > MAX_BUFFER_SIZE ? 0 : (_index + 1); })


static ssize_t receive_data(rawtcp_t* tcp_state);


/*
 Generic checksum calculation function
 */
static unsigned short csum(uint16_t *ptr, unsigned int nbytes)
{
	uint32_t sum;
	uint16_t answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		sum += *(unsigned char*) ptr;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
    answer = (unsigned short) ~sum;

	return (answer);
}

static void calculate_tcp_checksum(struct tcphdr* tcph,
		uint16_t tcp_payload_len, uint32_t src_addr, uint32_t dst_addr)
{
	pseudo_header psh;
	char* pseudogram;
	uint16_t tcphdr_len = (tcph->doff * WORD_LENGTH);

	// pseudoheader
	bzero(&psh, sizeof(pseudo_header));
	psh.source_address = src_addr;
	psh.dest_address = dst_addr;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(tcphdr_len + tcp_payload_len);

    size_t psize = sizeof(pseudo_header) + tcphdr_len + tcp_payload_len;
	pseudogram = malloc(psize);

	bzero(pseudogram, psize);
	memcpy(pseudogram, &psh, sizeof(pseudo_header));
	memcpy(pseudogram + sizeof(pseudo_header), tcph,
			tcphdr_len + tcp_payload_len);

	tcph->check = csum((uint16_t*) pseudogram, (unsigned int) psize);
	free(pseudogram);
}

static int validate_ip_checksum(struct iphdr* iph)
{
	int ret = -1;
	uint16_t received_checksum = iph->check;
	iph->check = 0;

	if (received_checksum
			== csum((uint16_t*) iph, (unsigned int) (iph->ihl * WORD_LENGTH)))
		ret = 1;

	return ret;
}

static int validate_tcp_checksum(rawtcp_t* tcp_state, struct tcphdr* tcph,
		uint16_t tcp_payload_length)
{
	int ret = -1;
	uint16_t received_checksum = tcph->check;
	tcph->check = 0;
	calculate_tcp_checksum(tcph, tcp_payload_length,
            *(uint32_t *) &tcp_state->session_info.dst_addr.sin_addr.s_addr,
            *(uint32_t *) &tcp_state->session_info.src_addr.sin_addr.s_addr);
	if (received_checksum == tcph->check)
		ret = 1;
	return ret;
}

static packet_t* create_packet()
{
	packet_t* packet = malloc(sizeof(packet_t));

	// send tcp syn
	bzero(packet, sizeof(packet_t));
	packet->offset[IP_OFFSET] = packet->payload;
	packet->offset[TCP_OFFSET] = packet->payload + sizeof(struct iphdr);
	packet->offset[DATA_OFFSET] = packet->payload + sizeof(struct tcphdr)
			+ sizeof(struct iphdr);
	return packet;
}

static void adjust_layer_offset(packet_t* packet)
{
	struct tcphdr *tcph;
	struct iphdr *iph;

	iph = (struct iphdr *) packet->payload;
	tcph = (struct tcphdr *) (packet->payload + (iph->ihl * WORD_LENGTH));
	packet->offset[TCP_OFFSET] = (char*) tcph;
	packet->offset[DATA_OFFSET] = (char*) (packet->offset[TCP_OFFSET]
			+ (tcph->doff * WORD_LENGTH));
}

static void destroy_packet(packet_t* packet)
{
	free(packet);
}


static void build_ip_header(rawtcp_t* tcp_state, struct iphdr* iph, uint16_t ip_payload_len)
{
    iph->daddr = *(uint32_t*) &tcp_state->session_info.dst_addr.sin_addr.s_addr;
    iph->saddr = *(uint32_t*) &tcp_state->session_info.src_addr.sin_addr.s_addr;
	iph->ihl = 5;
	iph->protocol = IPPROTO_TCP;
	iph->ttl = 255;
	iph->version = 4;
	iph->tot_len = sizeof(struct iphdr) + ip_payload_len;
	iph->check = csum((unsigned short*) iph, sizeof(struct iphdr));
}

static void build_tcp_header(rawtcp_t* tcp_state, struct tcphdr* tcph, tcp_flags_t* flags,
		uint16_t payload_len)
{
    tcph->dest = *(uint16_t*) &tcp_state->session_info.dst_addr.sin_port;
    tcph->source = *(uint16_t*) &tcp_state->session_info.src_addr.sin_port;
    tcph->window = htons(tcp_state->client_window_size);
    tcph->seq = htonl(tcp_state->client_next_seq_num);
    tcp_state->client_next_seq_num +=
			(flags->syn || flags->fin) ? 1 : payload_len;
	tcph->doff = (flags->syn) ? 6 : 5;
	tcph->syn = flags->syn;
	tcph->ack = flags->ack;
	tcph->fin = flags->fin;
	tcph->psh = flags->psh;
    tcph->ack_seq = htonl(tcp_state->server_next_seq_num);

	if (flags->syn)
	{
		char* tcp_options = ((char *) tcph) + sizeof(struct tcphdr);
		tcp_options_t mss =
		{ 0 };
		mss.option_type = 2;
		mss.option_len = 4;
		mss.option_value = htons(1460);
		memcpy(tcp_options++, &mss.option_type, sizeof(char));
		memcpy(tcp_options++, &mss.option_len, sizeof(char));
		memcpy(tcp_options, &mss.option_value, sizeof(uint16_t));
	}
}

static void build_packet_headers(rawtcp_t* tcp_state, packet_t* packet, int payload_len,
        tcp_flags_t* flags)
{
	struct tcphdr* tcph = (struct tcphdr*) packet->offset[TCP_OFFSET];
	struct iphdr* iph = (struct iphdr*) packet->offset[IP_OFFSET];

    build_tcp_header(tcp_state, tcph, flags, (uint16_t)payload_len);
    calculate_tcp_checksum(tcph, (uint16_t)payload_len,
            *(uint32_t *) &tcp_state->session_info.src_addr.sin_addr.s_addr,
            *(uint32_t *) &tcp_state->session_info.dst_addr.sin_addr.s_addr);
    build_ip_header(tcp_state, iph, ((tcph->doff * WORD_LENGTH) + (uint16_t)payload_len));
}

static ssize_t send_packet(rawtcp_t* tcp_state, void *buffer, size_t total_packet_len)
{
    ssize_t ret;
again:
    ret = sendto(tcp_state->session_info.send_fd, buffer,
            total_packet_len, 0,
            (struct sockaddr *) &tcp_state->session_info.dst_addr,
            sizeof(struct sockaddr_in)) ;
    if(ret<0)
    {
        if (errno == EINTR)
        {
            printf("Sendto() Interrupted!!");
            goto again;
        }
        else
        {
            perror("sendto failed");
            return -1;
        }
    }else if ((size_t)ret == total_packet_len){
        return (int)total_packet_len;
    }else{
        return -1;
    }
}


static ssize_t send_ack(rawtcp_t* tcp_state, uint8_t fin)
{
    ssize_t ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.ack = 1;
	flags.fin = fin;
    build_packet_headers(tcp_state, packet, 0, &flags);
    size_t payload_len = ((struct iphdr*) packet->offset[IP_OFFSET])->tot_len;
    if ((ret = send_packet(tcp_state, &packet->payload,payload_len)) != (ssize_t)payload_len)
	{
		printf("Send error!! Exiting.. ");
	}
    destroy_packet(packet);
	return ret;
}

static ssize_t receive_packet(rawtcp_t* tcp_state, packet_t *packet)
{
    ssize_t ret = -1;
	while (1)
	{
        if ((ret = recvfrom(tcp_state->session_info.recv_fd, &packet->payload,
                sizeof(packet->payload), MSG_DONTWAIT,
                NULL, NULL)) < 0)
		{
			if (errno == EINTR)
				continue;
            else if(errno == EAGAIN || errno == EWOULDBLOCK){
                //printf("block\n");
                usleep(100);
                continue;
            }else{
                perror("recv failed\n");
				return ret;
			}

		}
        printf("recvfrom %ld\n", ret);
		struct iphdr *iph = (struct iphdr *) &packet->payload;
		if (validate_ip_checksum(iph) < 0)
		{
			printf("IP Checksum validation failed!! Packet dropped!!\n");
			continue;
		}

		uint16_t iphdr_len = iph->ihl * WORD_LENGTH;
		struct tcphdr *tcph = (struct tcphdr *) ((char*) iph + iphdr_len);
		uint16_t tcphdr_len = tcph->doff * WORD_LENGTH;

        if (iph->saddr != tcp_state->session_info.dst_addr.sin_addr.s_addr
                && tcph->dest != tcp_state->session_info.src_port
                && tcph->source != tcp_state->session_info.dst_port){
            continue;
        }


        if (validate_tcp_checksum(tcp_state, tcph,
				(ntohs(iph->tot_len) - iphdr_len - tcphdr_len)) < 0)
		{
			printf("TCP Checksum validation failed!! Packet dropped!!\n");
			continue;
		}

		if ( IS_DUPLICATE_ACK(tcph))
		{
            printf("is duplicate ack");
			continue;
		}
		else if ( IS_DUPLICATE_TCP_SEGMENT(tcph))
		{
             printf("is duplicate segment");
            send_ack(tcp_state, 0);
			continue;
		}

		adjust_layer_offset(packet);
		packet->payload_len = (ntohs(iph->tot_len) - iphdr_len - tcphdr_len);
		break;
	}
	return ret;
}

static void process_ack(rawtcp_t* tcp_state, struct tcphdr *tcph, uint16_t payload_len)
{
    tcp_state->server_next_seq_num = (ntohl(tcph->seq) + payload_len);
    tcp_state->last_acked_seq_num = (ntohl(tcph->ack_seq));


    tcp_state->server_window_size = ntohs(tcph->window);
    tcp_state->cwindow_size =
            (++tcp_state->cwindow_size > MAX_CONGESTION_WINDOW_SIZE) ?
                    MAX_CONGESTION_WINDOW_SIZE : tcp_state->cwindow_size;

    //uint32_t ack = ntohl(tcph->ack_seq);
	if (HAS_TCP_OPTIONS(tcph))
	{
		char* tcp_options_offset = (char*) TCP_OPTION_OFFSET(tcph);
		uint16_t total_options_len = TCP_OPTIONS_LEN(tcph);

		while (!END_OF_TCP_OPTION_CHECK(tcp_options_offset)
				&& total_options_len > 0)
		{
			if ( IS_NO_OPERATION(tcp_options_offset))
			{
				tcp_options_offset++;
				total_options_len--;
			}
			else if ( IS_MSS(tcp_options_offset))
			{
                tcp_state->max_segment_size =
                        min(tcp_state->max_segment_size,
								*((uint16_t*)(tcp_options_offset+TCP_OPTION_DATA_OFFSET)));
				tcp_options_offset += OPTION_LENGTH(tcp_options_offset);
				total_options_len -= OPTION_LENGTH(tcp_options_offset);
			}
			else
			{
				tcp_options_offset += OPTION_LENGTH(tcp_options_offset);
				total_options_len -= OPTION_LENGTH(tcp_options_offset);
			}
		}
	}
}



static ssize_t send_flags(rawtcp_t* tcp, tcp_flags_t* flags)
{
	packet_t* packet = create_packet();
    build_packet_headers(tcp, packet, 0, flags);
    ssize_t ret = 0;
    int trycount = 0;
    uint32_t rrt = 0;
    ret = -1;
    do{
        uint32_t expected_ack_seq = tcp->last_acked_seq_num + 1;
        if ((ret = send_packet(tcp, &packet->payload,
                ((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
        {
            printf("[send_tcp_segment] send_packet error!!\n");
            goto EXIT;
        }
        usleep(10*1000 + rrt);
        rrt += (rrt==0)?(600*1000):rrt;
        if(receive_data(tcp)<0){
            printf("[send_tcp_segment] receive_data error\n");
            goto EXIT;
        }
        if(tcp->last_acked_seq_num == expected_ack_seq){
            printf("send segment success\n");
            ret = 0;
            break;
        }else{
            printf("[send_flags] not invalid seq, expected: %u, but: %u\n", expected_ack_seq, tcp->last_acked_seq_num);
        }
    }while(trycount++<5);
EXIT:
    return ret;
}

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


static ssize_t receive_data(rawtcp_t* tcp_state)
{
    ssize_t ret = -1;
    packet_t* packet = create_packet();
    struct tcphdr* tcph = NULL;
    struct iphdr* iph = NULL;

    if ((ret = receive_packet(tcp_state, packet)) < 0)
    {
        printf("Receive error!! Exiting.. \n");
        goto EXIT;
    }

    printf("payload data size: %d\n", packet->payload_len);
    tcph = (struct tcphdr *) packet->offset[TCP_OFFSET];
    iph = (struct iphdr*) packet->offset[IP_OFFSET];

    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_seq = ntohl(tcph->ack_seq);

    if (tcph->rst)
    {
        printf("[receive_data] received RST\n");
        send_ack(tcp_state, 0);
        tcp_state->tcp_read_end_closed = 1;
        tcp_state->tcp_write_end_closed = 1;
        tcp_state->tcp_current_state = CLOSED;
        ret = -1;
        goto EXIT;
    }

    if (packet->payload_len){
        printf("has payload copy it, %d\n", packet->payload_len);
        uint8_t* payload = packet->offset[DATA_OFFSET];
        outstream_writebuf(&tcp_state->outstream, payload, packet->payload_len);
        //log_hex("payload", packet->payload, packet->payload_len);
    }

    if(tcph->fin){
        printf("[receive_data] received Fin\n");
        ret = -1;
        if (tcp_state->tcp_current_state & ESTABLISHED)
        {
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 1);
            tcp_state->tcp_current_state = CLOSE_WAIT;
            tcp_state->tcp_read_end_closed = 1;
        }
        else if(tcp_state->tcp_current_state & FIN_WAIT_1)
        {
            if(tcph->ack && seq == tcp_state->server_next_seq_num){
                //received fin and ack
                process_ack(tcp_state, tcph, 1);
                send_ack(tcp_state, 0);
                tcp_state->tcp_read_end_closed = 1;
                //TIME_WAIT is managered by os. application cannnot controll it.
                //SO just set CLOSED.
                tcp_state->tcp_current_state = CLOSED;
            }else{
                //received fin, but no ack
                process_ack(tcp_state, tcph, 1);
                send_ack(tcp_state, 0);
                tcp_state->tcp_read_end_closed = 1;
                tcp_state->tcp_current_state = CLOSING;
            }
        }
        else if (tcp_state->tcp_current_state & FIN_WAIT_2)
        {
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 0);
            tcp_state->tcp_read_end_closed = 1;
            tcp_state->tcp_current_state = CLOSED;
        }else{
            //impossible.
            printf("impossible state: %d\n", tcp_state->tcp_current_state);
        }
    }else if(tcph->syn && tcph->ack && (tcp_state->tcp_current_state & SYN_SENT)){
        printf("[receive_data] received Sync\n");
        process_ack(tcp_state, tcph, 1);
        send_ack(tcp_state, 0);
        tcp_state->tcp_current_state = ESTABLISHED;
        ret = 0;
    }else if(tcph->psh){
        printf("[receive_data] received Push, flag: %d,  payload len: %d\n", tcph->psh, packet->payload_len);
        process_ack(tcp_state, tcph, packet->payload_len);
        if ( ((tcp_state->tcp_current_state & CLOSING)
                || (tcp_state->tcp_current_state & LAST_ACK)) && seq == tcp_state->server_next_seq_num)
        {
            ret = -1;
            tcp_state->tcp_current_state = CLOSED;
        }else if ( (tcp_state->tcp_current_state & FIN_WAIT_1)  && seq == tcp_state->server_next_seq_num ){
            ret = -1;
            tcp_state->tcp_current_state = FIN_WAIT_2;
        }else{
            ret = 0;
        }
        send_ack(tcp_state, 0);
    }else if(tcph->ack){
         printf("[receive_data] received ack\n");
         process_ack(tcp_state, tcph, packet->payload_len);
         send_ack(tcp_state, 0);
    }
EXIT:
    destroy_packet(packet);
    return ret;
}


rawtcp_t* rawtcp_connect(const char* dest_ip, int dst_port)
{
    ssize_t ret = 0;
    int send_sock_fd = -1, recv_sock_fd = -1;

    struct hostent *host_details = NULL;
    if (NULL == (host_details = gethostbyname(dest_ip)))
    {
        printf("ERROR: Failed to resolve hostname: %s\n", dest_ip);
        return NULL;
    }
    /** local address */
    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(struct sockaddr_in));
    uint32_t src_address = getLocalIPAddress(
            ((struct in_addr *) host_details->h_addr)->s_addr);
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(random());
    src_addr.sin_addr = *(struct in_addr *) &src_address;


    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    dst_addr.sin_addr = *((struct in_addr *) host_details->h_addr);


    char psrc_addr[256] = { 0 };
    char pdst_addr[256] = { 0 };
    printf("Src Address: %s Destination Address: %s\n",
            inet_ntop(AF_INET, &src_addr.sin_addr.s_addr, psrc_addr, 256),
            inet_ntop(AF_INET, &dst_addr.sin_addr.s_addr, pdst_addr, 256));

    send_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (send_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        return NULL;
    }

    recv_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (recv_sock_fd < 0)
    {
        printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
        return NULL;
    }

    if (bind(recv_sock_fd, (const struct sockaddr *) &src_addr,
            sizeof(struct sockaddr_in)) < 0)
    {
        printf("Error: Unable to bind the receiving socket: %s\n",
                strerror(errno));
        return NULL;
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;

    if (setsockopt(recv_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        return NULL;
    }

    rawtcp_t* tcp = (rawtcp_t*)malloc(sizeof(rawtcp_t));
    bzero(tcp, sizeof(rawtcp_t));
    tcp->max_segment_size = MAX_CLIENT_SEGMENT_SIZE;
    tcp->client_window_size = CLIENT_WINDOW_SIZE;
    tcp->client_next_seq_num = (uint32_t)random(); // STARTING_SEQUENCE;
    tcp->last_acked_seq_num = tcp->client_next_seq_num;
    tcp->session_info.dst_addr = dst_addr;
    tcp->session_info.src_addr = src_addr;
    tcp->session_info.recv_fd = recv_sock_fd;
    tcp->session_info.send_fd = send_sock_fd;
    tcp->syn_retries = 5;
    tcp->cwindow_size = 1;
    tcp->tcp_current_state = SYN_SENT;

	tcp_flags_t flags ={ 0 };
    flags.syn = 1;
    flags.ack = 0;
    send_flags(tcp, &flags);
    if(tcp->tcp_current_state == ESTABLISHED){
        printf("[rawtcp_connect] tcp connected");
        return tcp;
    }else{
        printf("[rawtcp_connect] Failed to set up TCP Connection!!\n");
        close(send_sock_fd);
        close(recv_sock_fd);
        FREEIF(tcp->outstream.data);
        return NULL;
	}

}


void rawtcp_close(rawtcp_t* tcp)
{
    if(tcp == NULL){
        return;
    }
    tcp_flags_t flags = {0};
    flags.fin = 1;
    flags.ack = 1;
    send_flags(tcp, &flags);
    usleep(10*1000);
    tcp->tcp_write_end_closed = 1;
    close(tcp->recv_fd);
    close(tcp->send_fd);
    FREEIF(tcp->outstream.data);
    free(tcp);
}

/**
 * @brief rawtcp_send
 * @param tcp_state
 * @param buffer
 * @param buffer_len
 * @return return 0 if success, -1 if failed
 */
int rawtcp_send(rawtcp_t* tcp_state, const char* buffer, size_t buffer_len)
{
    printf("rawtcp_send\n");
    int ret = -1;
    size_t total_bytes_to_be_sent = buffer_len;
    tcp_flags_t flags = { 0 };
	flags.psh = 1;
    flags.ack = 1;

	while (total_bytes_to_be_sent > 0)
	{
		packet_t* packet = create_packet();
        packet->payload_len = total_bytes_to_be_sent > tcp_state->max_segment_size ?
                    tcp_state->max_segment_size : (uint16_t)total_bytes_to_be_sent;
		memcpy(packet->offset[DATA_OFFSET], buffer, packet->payload_len);
        build_packet_headers(tcp_state, packet, packet->payload_len, &flags);

        int trycount = 0;
        uint32_t rrt = 0;
        ret = -1;
        do{
            uint32_t expected_ack_seq = tcp_state->last_acked_seq_num + packet->payload_len;
            if ((ret = send_packet(tcp_state, &packet->payload,
                    ((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
            {
                printf("Send error!! Exiting..\n");
                break;
            }
            usleep(10*1000 + rrt);
            rrt += (rrt==0)?(600*1000):rrt;
            receive_data(tcp_state);
            if(tcp_state->last_acked_seq_num == expected_ack_seq){
                printf("send segment success\n");
                ret = 0;
                break;
            }else{
                printf("not invalid seq");
            }
        }while(trycount++<5);
        destroy_packet(packet);
        if(ret == -1){
            goto EXIT;
        }
		total_bytes_to_be_sent -= packet->payload_len;
	}
EXIT:
    return ret;
}

#ifndef MIN
#define MIN(a, b) ((a)<(b))?(a):(b)
#endif

int rawtcp_recv(rawtcp_t* tcp, char* buffer, int buffer_len){
    if(tcp->outstream.data_len<=0){
        if(tcp->tcp_current_state != ESTABLISHED){
            printf("tcp closed\n");
            return -1;
        }else{
            receive_data(tcp);
           return 0;
        }
    }else{
        int minsize = MIN(buffer_len, tcp->outstream.data_len);
        int remain = tcp->outstream.data_len - minsize;
        printf("copy data out, %d, remain: %d\n", minsize, remain);
        memcpy(buffer, tcp->outstream.data, minsize);
        tcp->outstream.data_len = remain;
        if(remain>0){
            memmove(tcp->outstream.data, tcp->outstream.data + minsize, remain);
        }
        return minsize;
    }
}




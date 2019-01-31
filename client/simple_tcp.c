/*
 * tcp_handler.c
 *
 *  Created on: Dec 8, 2015
 *      Author: Praveen
 */
#include <stdlib.h>
#include "simple_tcp.h"


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


static inline uint64_t utc_timestamp(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)((uint64_t)tv.tv_sec * 1000) + (uint64_t)tv.tv_usec/1000;
}


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
	answer = (short) ~sum;

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

	int psize = sizeof(pseudo_header) + tcphdr_len + tcp_payload_len;
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

    build_tcp_header(tcp_state, tcph, flags, payload_len);
	calculate_tcp_checksum(tcph, payload_len,
            *(uint32_t *) &tcp_state->session_info.src_addr.sin_addr.s_addr,
            *(uint32_t *) &tcp_state->session_info.dst_addr.sin_addr.s_addr);
    build_ip_header(tcp_state, iph, ((tcph->doff * WORD_LENGTH) + payload_len));
}

static int send_packet(rawtcp_t* tcp_state, void *buffer, int total_packet_len)
{
	int ret = -1;

	while (total_packet_len > 0)
	{
		//Send the packet
        if ((ret = sendto(tcp_state->session_info.send_fd, buffer,
				total_packet_len, 0,
                (struct sockaddr *) &tcp_state->session_info.dst_addr,
				sizeof(struct sockaddr_in))) < 0)
		{
			if (errno == EINTR)
			{
				printf("Sendto() Interrupted!!");
				continue;
			}
			else
			{
				perror("sendto failed");
				goto EXIT;
			}
		}
		if (ret == total_packet_len)
			break;

		total_packet_len -= ret;
		buffer += ret;
	}
    EXIT:
	return ret;
}


static int send_ack(rawtcp_t* tcp_state, uint8_t fin)
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.ack = 1;
	flags.fin = fin;
    build_packet_headers(tcp_state, packet, 0, &flags);

    if ((ret = send_packet(tcp_state, &packet->payload,
			((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
	{
		printf("Send error!! Exiting.. ");
	}

	EXIT: destroy_packet(packet);
	return ret;
}

static int receive_packet(rawtcp_t* tcp_state, packet_t *packet)
{
	int ret = -1;
	while (1)
	{
        if ((ret = recvfrom(tcp_state->session_info.recv_fd, &packet->payload,
                sizeof(packet->payload), MSG_DONTWAIT,
                NULL, NULL)) < 0)
		{
			if (errno == EINTR)
				continue;
            else if(errno == EAGAIN || errno == EWOULDBLOCK){
                usleep(100);
                continue;
            }else{
				perror("recv failed");
				return ret;
			}

		}
        printf("recvfrom %d\n", ret);
		//Data received successfully
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
                && tcph->source != tcp_state->session_info.dst_port)
			continue;

        if (validate_tcp_checksum(tcp_state, tcph,
				(ntohs(iph->tot_len) - iphdr_len - tcphdr_len)) < 0)
		{
			printf("TCP Checksum validation failed!! Packet dropped!!\n");
			continue;
		}

		if ( IS_DUPLICATE_ACK(tcph))
		{
            //handle_packet_retransmission();
			continue;
		}
		else if ( IS_DUPLICATE_TCP_SEGMENT(tcph))
		{
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

    uint32_t ack = ntohl(tcph->ack_seq);
    //remove_acked_entries(ntohl(tcph->ack_seq));

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


static int send_tcp_segment(rawtcp_t* tcp_state, packet_t* packet)
{
	int ret = 0;

    if ((ret = send_packet(tcp_state, &packet->payload,
			((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
	{
		printf("Send error!! Exiting.. ");
		goto EXIT;
	}

	EXIT: return ret;
}

static int send_syn(rawtcp_t* tcp_state)
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.syn = 1;
    build_packet_headers(tcp_state, packet, 0, &flags);
    tcp_state->tcp_current_state = SYN_SENT;

    return send_tcp_segment(tcp_state, packet);
}

static int receive_syn_ack(rawtcp_t* tcp_state, tcp_flags_t* flags)
{
	int ret = -1;
	packet_t* packet = create_packet();
	struct tcphdr *tcph;

	while (1)
	{
        if ((ret = receive_packet(tcp_state, packet)) < 0)
		{
			printf("Receive error!! Exiting.. ");
			goto EXIT;
		}
        printf("[receive_syn_ack] received packet");
		tcph = (struct tcphdr *) packet->offset[TCP_OFFSET];

        if (tcph->ack == flags->ack && tcph->syn == flags->syn){
			break;
        }

        if (tcph->rst || !tcp_state->syn_retries)
		{
			ret = -1;
			goto EXIT;
		}
	}

    process_ack(tcp_state, tcph, 1);

	EXIT: destroy_packet(packet);
	return ret;
}

static int receive_data(rawtcp_t* tcp_state)
{
    int ret = -1;
    packet_t* packet = create_packet();
    struct tcphdr* tcph = NULL;
    struct iphdr* iph = NULL;

    if ((ret = receive_packet(tcp_state, packet)) < 0)
    {
        printf("Receive error!! Exiting.. ");
        goto EXIT;
    }

    printf("payload data size: %d\n", packet->payload_len);
    tcph = (struct tcphdr *) packet->offset[TCP_OFFSET];
    iph = (struct iphdr*) packet->offset[IP_OFFSET];

    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_seq = ntohl(tcph->ack_seq);

    tcp_state->last_acked_seq_num = ack_seq;
    tcp_state->server_next_seq_num = seq + packet->payload_len;

    if (tcph->rst)
    {
        printf("received RST");
        ret = -1;
        goto EXIT;
    }

    if (seq != (tcp_state->server_next_seq_num))
    {
        send_ack(tcp_state, 0);
    }

    if(packet->payload_len>0){
        tcp_state->server_next_seq_num = seq + packet->payload_len;
        //copy content;
    }

    //process_ack(tcp_state, tcph, 1);

EXIT:
    destroy_packet(packet);
    return ret;
}


static void get_wait_time(struct timespec* timeToWait, uint16_t timeInSeconds)
{
	struct timeval now;
	int rt;
	gettimeofday(&now, NULL);
	timeToWait->tv_sec = now.tv_sec + timeInSeconds;
	timeToWait->tv_nsec = 0;
}


static void handle_received_data(rawtcp_t* tcp_state, packet_t* packet)
{
    tcp_state->client_window_size -= packet->payload_len;
    tcp_state->client_window_size =
            (tcp_state->client_window_size < 0) ?
                    0 : tcp_state->client_window_size;
    tcp_state->recv_info.recv_buffer[tcp_state->recv_info.recv_buffer_tail].packet =
			packet;

    if ( WRAP_ROUND_BUFFER_SIZE(tcp_state->recv_info.recv_buffer_tail)
         == tcp_state->recv_info.recv_buffer_head){

    }


    tcp_state->recv_info.recv_buffer_tail =
    WRAP_ROUND_BUFFER_SIZE(tcp_state->recv_info.recv_buffer_tail);
}

static void tcp_recv_handler(rawtcp_t* tcp_state)
{
	packet_t* packet = NULL;
	struct tcphdr* tcph = NULL;
	struct iphdr* iph = NULL;
	int ret = 0;

	while (1)
	{
		packet = create_packet();
        if ((ret = receive_packet(tcp_state, packet)) < 0)
		{
			printf("Receive error!! Exiting.. ");
			continue;
		}

		tcph = (struct tcphdr*) packet->offset[TCP_OFFSET];
		iph = (struct iphdr*) packet->offset[IP_OFFSET];

        if (ntohl(tcph->seq) != (tcp_state->server_next_seq_num))
		{
            send_ack(tcp_state, 0);
			destroy_packet(packet);
			continue;
		}

		uint16_t payload_len = ntohs(iph->tot_len) - (iph->ihl * WORD_LENGTH)
				- (tcph->doff * WORD_LENGTH);

		if (tcph->rst)
		{
            send_ack(tcp_state, 0);
            tcp_state->tcp_read_end_closed = 1;
            tcp_state->tcp_write_end_closed = 1;
            tcp_state->tcp_current_state = CLOSED;
			break;
		}

		if (packet->payload_len)
            handle_received_data(tcp_state, packet);

        if (tcph->fin && (tcp_state->tcp_current_state & ESTABLISHED))
		{
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 0);
            tcp_state->tcp_current_state = CLOSE_WAIT;
            tcp_state->tcp_read_end_closed = 1;
			continue;
		}
		else if (tcph->fin && tcph->ack
                && (tcp_state->tcp_current_state & FIN_WAIT_1))
		{
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 0);
            tcp_state->tcp_read_end_closed = 1;
            tcp_state->tcp_current_state = CLOSED;
			break;
		}
        else if (tcph->fin && (tcp_state->tcp_current_state & FIN_WAIT_1))
		{
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 0);
            tcp_state->tcp_read_end_closed = 1;
            tcp_state->tcp_current_state = CLOSING;
			continue;
		}
        else if (tcph->fin && (tcp_state->tcp_current_state & FIN_WAIT_2))
		{
            process_ack(tcp_state, tcph, 1);
            send_ack(tcp_state, 0);
            tcp_state->tcp_read_end_closed = 1;
            tcp_state->tcp_current_state = CLOSED;
			break;
		}

        process_ack(tcp_state, tcph, payload_len);

		if (packet->payload_len == 0)
		{
			destroy_packet(packet);

            if ((tcp_state->tcp_current_state & CLOSING)
                    || (tcp_state->tcp_current_state & LAST_ACK))
			{
                tcp_state->tcp_current_state = CLOSED;
                break;
			}

            if (tcp_state->tcp_current_state & FIN_WAIT_1)
                tcp_state->tcp_current_state = FIN_WAIT_2;

			continue;
		}

        send_ack(tcp_state, 0);
	}

	return NULL;
}


//Blocking call
rawtcp_t* rawtcp_connect(const char* dest_ip, int dst_port)
{
	int ret = 0;
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

    rawtcp_t* tcp_state = (rawtcp_t*)malloc(sizeof(rawtcp_t));

// Initialize the TCP Session State with the given details
    bzero(tcp_state, sizeof(rawtcp_t));
    tcp_state->max_segment_size = MAX_CLIENT_SEGMENT_SIZE;
    tcp_state->client_window_size = CLIENT_WINDOW_SIZE;
    tcp_state->client_next_seq_num = random(); // STARTING_SEQUENCE;
    tcp_state->session_info.dst_addr = dst_addr;
    tcp_state->session_info.src_addr = src_addr;
    tcp_state->session_info.recv_fd = recv_sock_fd;
    tcp_state->session_info.send_fd = send_sock_fd;
    tcp_state->syn_retries = 5;
    tcp_state->cwindow_size = 1;

	tcp_flags_t flags ={ 0 };
	flags.ack = 1;
	flags.syn = 1;
    if (((ret = send_syn(tcp_state)) < 0)
            || ((ret = receive_syn_ack(tcp_state, &flags)) < 0) ||
            ((ret = send_ack(tcp_state, 0)) < 0))
	{
		printf("Failed to set up TCP Connection!!");
		ret = -1;
        goto EXIT;
	}

    tcp_state->tcp_current_state = ESTABLISHED;
    return tcp_state;

EXIT:
    if(tcp_state != NULL){
        free(tcp_state);
    }
    return NULL;
}

static int send_fin(rawtcp_t* tcp_state)
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.fin = 1;
	flags.ack = 1;
    build_packet_headers(tcp_state, packet, 0, &flags);

    return send_tcp_segment(tcp_state, packet);
}

int rawtcp_close(rawtcp_t* tcp_state)
{
	int ret = -1;

    if (!((tcp_state->tcp_current_state & ESTABLISHED)
            || (tcp_state->tcp_current_state & CLOSE_WAIT)))
	{
		goto EXIT;
	}

    if ((ret = send_fin(tcp_state)) < 0)
		goto EXIT;

	struct timespec timeToWait;
	get_wait_time(&timeToWait, 10);
    if (tcp_state->tcp_current_state & ESTABLISHED)
        tcp_state->tcp_current_state = FIN_WAIT_1;
	else
        tcp_state->tcp_current_state = LAST_ACK;
    usleep(10*1000);
    tcp_state->tcp_write_end_closed = 1;
	EXIT: return ret;
}

int rawtcp_send(rawtcp_t* tcp_state, char* buffer, int buffer_len)
{
    printf("rawtcp_send\n");
	int ret = 0;
	int total_bytes_to_be_sent = buffer_len;
    tcp_flags_t flags = { 0 };
	flags.psh = 1;
    flags.ack = 1;

	while (total_bytes_to_be_sent > 0)
	{
        if (tcp_state->tcp_write_end_closed)
		{
			printf("TCP Client Closed!!\n");
			ret = -1;
			break;
		}

		packet_t* packet = create_packet();
		packet->payload_len =
                total_bytes_to_be_sent > tcp_state->max_segment_size ?
                        tcp_state->max_segment_size : total_bytes_to_be_sent;

		memcpy(packet->offset[DATA_OFFSET], buffer, packet->payload_len);
        build_packet_headers(tcp_state, packet, packet->payload_len, &flags);

        int rrt = 600; //ms
        while(1){
            uint32_t snd_seq = tcp_state->last_acked_seq_num;
            uint32_t ack_seq = tcp_state->last_acked_seq_num + packet->payload_len;
            if ((ret = send_packet(tcp_state, &packet->payload,
                    ((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
            {
                printf("Send error!! Exiting..\n");
                goto EXIT;
            }
            usleep(10*1000 + rrt);
            rrt *= 2;
            receive_data(tcp_state);
            if(tcp_state->last_acked_seq_num == ack_seq){
                printf("received ack\n");
                break;
            }else{
                printf("not invalid seq");
            }
        }
		total_bytes_to_be_sent -= packet->payload_len;
		ret += packet->payload_len;
	}

EXIT:
    return ret;
}

static void release_and_update_recv_buffer(rawtcp_t* tcp_state, packet_t* packet)
{

    tcp_state->recv_info.recv_buffer[tcp_state->recv_info.recv_buffer_head].packet =
	NULL;
    tcp_state->recv_info.recv_buffer_head =
    WRAP_ROUND_BUFFER_SIZE(tcp_state->recv_info.recv_buffer_head);
	destroy_packet(packet);
}


/******************************************
 * Filename: ping.c
 * Author: zhangwj 
 * Description: a simple ping program
 * Date: 2017-05-23
 * Warnning:
*******************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>

#define MAX_PACKET		128

typedef struct packet_info_t {
	int seq; /* sequence number */
	struct timeval start_time;
}packet_t;

typedef struct ping_info_t {
	char hostname[32];
	int raw_sock;
	int alive;
	int send_count;
	int recv_count;
	struct timeval start_time;
	packet_t packet[MAX_PACKET];	
}ping_info_t;

pid_t pid;
ping_info_t * g_pinfo = NULL;

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static void tv_interval(struct timeval start_time, struct timeval *interval)
{	
	gettimeofday(interval, NULL);
	tvsub(interval, &start_time);
}

void ping_end()
{
	g_pinfo->alive = 0;
}

void sigexit(int signo)
{
	ping_end();
}

int global_init()
{
	g_pinfo = (ping_info_t *)malloc(sizeof(ping_info_t));
	if (NULL == g_pinfo) {
		fprintf(stderr, "ping allocate memory failure, Error:[%d:%s]\n", errno, strerror(errno));
		return -1;
	}
	memset(g_pinfo, 0, sizeof(ping_info_t));
	g_pinfo->alive = 1;
	
	pid = getpid();
	signal(SIGINT, sigexit);
}

void print_show(void *buf, int len)
{
	long triptime;  //round trip time
	struct timeval start_time;
	struct timeval offset_time;
	struct ip * ip_hdr;
	struct icmp * icmp;

	ip_hdr = (struct ip *)buf;
	icmp = (struct icmp *)(buf + (ip_hdr->ip_hl << 2));	

	start_time = g_pinfo->packet[icmp->icmp_seq].start_time;
	tv_interval(start_time, &offset_time);
	triptime = offset_time.tv_sec * 1000 * 1000 + offset_time.tv_usec;
	
	printf("%d byte from %s: icmp_seq=%u ttl=%d",
		len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl);        
	
	if (triptime >= 100000)
		printf(" time=%ld ms", triptime/1000);
	else if (triptime >= 10000)
		printf(" time=%ld.%01ld ms", triptime/1000, (triptime%1000)/100);
	else if (triptime >= 1000) 
		printf(" time=%ld.%02ld ms", triptime/1000, (triptime%1000)/10);
	else
		printf(" time=%ld.%03ld ms", triptime/1000, triptime%1000);
	
	printf("\n");

}

/*
 * finish
 * print out statistics 
 */
void finish(void) 
{
	struct timeval offset_time;
	tv_interval(g_pinfo->start_time, &offset_time);
	putchar('\n');
	fflush(stdout);
	printf("--- %s ping statistics ---\n", g_pinfo->hostname);

	printf("%ld packets transmitted, ", g_pinfo->send_count);
	printf("%ld received", g_pinfo->recv_count);
	if (g_pinfo->send_count)
		printf(", %d%% packet loss", 
				(int) ((((long long)(g_pinfo->send_count - g_pinfo->recv_count)) * 100) /
					 g_pinfo->send_count));
	printf(", time %ldms", 1000*offset_time.tv_sec+offset_time.tv_usec/1000);

	printf("\n");
	
}

/* »Ø¹öËã·¨ */
unsigned short in_cksum(unsigned short *addr, int len, unsigned short csum)
{
	int nleft = len;
	unsigned short *w = addr;
	unsigned short answer = 0;
	int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum += answer; /* le16toh() may be unavailable on old systems */
	} 

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void icmp_echo_set(struct icmp *icmphdr, int seq, int length)
{
	icmphdr->icmp_type = ICMP_ECHO;
	icmphdr->icmp_code = 0;
	icmphdr->icmp_cksum = 0;
	icmphdr->icmp_seq = seq;
	icmphdr->icmp_id = pid & 0xffff;
	icmphdr->icmp_cksum = in_cksum((unsigned short*)icmphdr, length, 0);
}

int icmp_parse_reply(void *buf, int len)
{
	int offset;
	struct ip * ip_hdr;
	struct icmp * icmp;
	
	ip_hdr = (struct ip *)buf;
	offset = ip_hdr->ip_hl << 2;
	icmp = (struct icmp*)(buf + offset);
	
	/* filter */
	if (((len - offset) < 8)) {
		fprintf(stderr, "Invalid packet, icmp_hdr >= 8\n");
		return -1;
    }

	switch(icmp->icmp_type) {
	case ICMP_ECHOREPLY:
		if (icmp->icmp_id == pid & 0xffff) {
        	if ((icmp->icmp_seq >= 0) && (icmp->icmp_seq < MAX_PACKET)) {
				print_show(buf, (len - offset));
				return 0;
			} 
			else if (icmp->icmp_seq == MAX_PACKET) {
				ping_end();
				return -1;
			}
		}
		break;
	default:
		break;
	}

	return -1;
}

void * ping_send(void *args)
{
	int send_count;
	int size;
	char send_buf[128];
	struct sockaddr_in * dest = NULL;

	dest = (struct sockaddr_in *)args;
	gettimeofday(&g_pinfo->start_time, NULL);
	memset(send_buf, 0, sizeof(send_buf));
	while (g_pinfo->alive) {
		gettimeofday(&(g_pinfo->packet[g_pinfo->send_count].start_time), NULL);
		icmp_echo_set((struct icmp *)send_buf, g_pinfo->send_count, 64);
		size = sendto(g_pinfo->raw_sock, send_buf, 64, 0, (struct sockaddr *)dest, sizeof(struct sockaddr));
		g_pinfo->send_count++;
		if (size < 0) {
			fprintf(stderr, "icmp packet failure, Error[%d:%s]", errno, strerror(errno));	
			continue;
		}
		sleep(1);
	}
}

void * ping_recv(void *args)
{
	int ret;
	int size;
	struct timeval tv;
	char recv_buf[128];
	fd_set rfd;
	
	tv.tv_sec = 0;
	tv.tv_usec = 300;
	memset(recv_buf, 0 ,sizeof(recv_buf));
	while(g_pinfo->alive) {	

		FD_ZERO(&rfd);
		FD_SET(g_pinfo->raw_sock, &rfd);
		ret = select(g_pinfo->raw_sock + 1, &rfd, NULL, NULL, &tv);
		switch(ret) {
		case -1:
			fprintf(stderr, "select error, Error[%d:%s]\n", errno, strerror(errno));
			break;
		case 0: /* timeout */
			break;
		default:
			if (FD_ISSET(g_pinfo->raw_sock, &rfd)) {
				size = recv(g_pinfo->raw_sock, recv_buf, sizeof(recv_buf), 0);
				if (size < 0) {
					continue;	
				}
				if (icmp_parse_reply(recv_buf, size) == 0) {
					g_pinfo->recv_count++; 				
				}
				break;
			}
		}
	}
}

int ping4_run(int argc, char **argv, struct addrinfo *ai)			
{
	int size;
	int ret;
	int raw_sock;
	struct sockaddr_in addr;
	pthread_t send_id, recv_id;
	
	if (NULL == ai) {
		return -1;	
	}
	
	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (raw_sock < 0) {
		fprintf(stderr, "socket create failure\n");
		return -1;
	}

	size = 128 * 1024; //128k
	ret = setsockopt(raw_sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (ret < 0) {
		fprintf(stderr, "setsockopt failure, Error:[%d:%s]", errno, strerror(errno));
		close(raw_sock);
		return -1;
	}
	g_pinfo->raw_sock = raw_sock;

	bzero(&addr, sizeof(addr));	
	memcpy(&addr, (struct sockaddr_in *)ai->ai_addr, sizeof(addr));

	printf("PING %s, (%s) 56(84) bytes of data.\n", argv[1], inet_ntoa(addr.sin_addr));

	strncpy(g_pinfo->hostname, inet_ntoa(addr.sin_addr), 32);
	ret = pthread_create(&send_id, NULL,(void *)ping_send, (void *)&addr);
	if (ret < 0) {
		fprintf(stderr, "create ping send thread failure, Error:[%d:%s]", errno, strerror(errno));
		close(raw_sock);
		return -1;	
	}
	
	ret = pthread_create(&recv_id, NULL, (void *)ping_recv, (void *)&addr);
	if (ret < 0) {
		fprintf(stderr, "create ping recv thread failure, Error:[%d:%s]", errno, strerror(errno));
		close(raw_sock);
		return -1;	
	}
	
	/* wait thread end */
	pthread_join(send_id, NULL);
	pthread_join(recv_id, NULL);

	finish();

	close(raw_sock);
	return 0;
}


int main(int argc, char **argv)
{
	int status;
	char *target;
	struct addrinfo hints;
	struct addrinfo *result, *ai;
	
	if (argc != 2) {
		printf("Usage ping <ip or domain name>\n");
		exit(1);
	}
	
	if (global_init()) {
		return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_protocol = 0;          /* Any protocol */
	
	target = argv[1];
	status = getaddrinfo(target, NULL, &hints, &result);
	if (status != 0) {
		fprintf(stderr, "ping: %s: %s\n", target, gai_strerror(status));
		exit(1);	
	}
	
	for (ai = result; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		case AF_INET:
			status = ping4_run(argc, argv, ai);
			break;
		case AF_INET6:
			 printf("AF_INET6 (IPv6)\n");
			break;
		default:
			fprintf(stderr, "ping: unknown protocol family: %d\n", ai->ai_family);
			exit(1);
		}
		
		if (status == 0)
			break;
	}
	freeaddrinfo(result);
		
	return 0;
}

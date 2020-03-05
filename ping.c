#include <signal.h>
#include <math.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define IP_HEADER_SIZE 20
#define ECHO_REQUEST_SIZE 8
#define PACKET_SIZE 56

typedef struct t_send_hdr
{
	struct icmphdr	icmp_hdr;
	struct timeval	time;
}__attribute__((packed, aligned(64))) s_send_hdr;

typedef struct		s_statistics
{
	char			addr[INET_ADDRSTRLEN];
	double			time;
	int				recv_packets;
	double			rtt_avg;
	double			rtt_max;
	double			rtt_mdev;
	double			rtt_min;
	double			rtt_total;
	double			rtt_sqrsum;
	struct timeval	start_time;
	struct timeval	stop_time;
	int				tran_packets;
}					t_statistics;

typedef struct	s_data
{
	struct t_send_hdr	send_hdr;
	struct t_send_hdr	recv_hdr;
	struct msghdr		recv_msg;
	struct iovec		recv_vec;
	struct sockaddr_in	*src_addr;
	int					sock;

	struct s_statistics stats;
}				t_data;

struct s_data	data;

int				check_user(void)
{
	int uid;

	uid = getuid();
	if (uid == 0)
		return 0;
	return 1;
}

struct addrinfo	*get_destination(const char *src)
{
	struct	addrinfo *res;
	struct	addrinfo hints;

	res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if (!getaddrinfo(src, 0, &hints, &res)) {
		inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, data.stats.addr, INET_ADDRSTRLEN);
		printf("PING %s (%s) %i(%i) bytes of data.\n", src, data.stats.addr, PACKET_SIZE, PACKET_SIZE + IP_HEADER_SIZE + ECHO_REQUEST_SIZE);
	}
	return res;
}

struct t_send_hdr	get_dgram(struct addrinfo *ainfo)
{
	struct t_send_hdr send_hdr;
	struct sockaddr_in	*addr;

	addr = (struct sockaddr_in*)ainfo->ai_addr;
	memset(&send_hdr.icmp_hdr, 0, sizeof(send_hdr.icmp_hdr));
	send_hdr.icmp_hdr.type = ICMP_ECHO;
	send_hdr.icmp_hdr.un.echo.id = 1243;
	send_hdr.icmp_hdr.un.echo.sequence = 0;

	return send_hdr;
}

void			setsockopts(int sock)
{
	int					yes = 1;
	int					ttl;

	ttl = IPDEFTTL;
	setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes));
	setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

int				get_ttl(struct msghdr recv_msg)
{
	int ttl = -1;
	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&recv_msg); 

	for (; cmsg; cmsg = CMSG_NXTHDR(&recv_msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
			uint8_t * ttlPtr = (uint8_t *)CMSG_DATA(cmsg);
			ttl = *ttlPtr;
			break;
		}
	}
	return (ttl);
}

struct msghdr	set_recvmsg(struct iovec *recv_vec, struct t_send_hdr *recv_hdr, struct sockaddr_in *src_addr)
{
	struct msghdr		recv_msg;
	uint8_t				ctrlDataBuffer[CMSG_SPACE(sizeof(uint8_t))];

	recv_vec->iov_base = recv_hdr;
	recv_vec->iov_len = sizeof(*recv_hdr);

	memset(&recv_msg, 0, sizeof(recv_msg));
	recv_msg.msg_iov = recv_vec;
	recv_msg.msg_iovlen = 1;
	recv_msg.msg_name = src_addr;
	recv_msg.msg_namelen = sizeof(*src_addr);
	recv_msg.msg_control = ctrlDataBuffer;
	recv_msg.msg_controllen = sizeof(ctrlDataBuffer);

	return recv_msg;
}

double			get_time(struct timeval send, struct timeval recv)
{
	double time;

	time = (recv.tv_sec - send.tv_sec) * 1000. + (recv.tv_usec - send.tv_usec) / 1000.;
	return time;
}

void			set_socket(struct addrinfo *ainfo)
{
	data.src_addr = (struct sockaddr_in*)ainfo->ai_addr;
	data.send_hdr = get_dgram(ainfo);

	data.recv_msg = set_recvmsg(&data.recv_vec, &data.recv_hdr, data.src_addr);

	data.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	setsockopts(data.sock);
	if (data.sock < 0) {
		perror("socket");
	}
}

void			send_packet()
{
	long double	time;

	gettimeofday(&data.stats.stop_time, NULL);
	if (data.stats.start_time.tv_usec == 0 && data.stats.start_time.tv_sec == 0) {
		time = 0;
	} else {
		time = get_time(data.stats.start_time, data.stats.stop_time);
		data.stats.time += time;
	}

	gettimeofday(&data.send_hdr.time, NULL);
	data.send_hdr.icmp_hdr.un.echo.sequence++;
	if (sendto(data.sock, &data.send_hdr, sizeof(data.send_hdr), 0, (struct sockaddr*)data.src_addr, sizeof(*data.src_addr)) < 0) {
		perror("ping: sendto");
		data.stats.tran_packets++;
		alarm(1);
		return ;
	}
	data.stats.tran_packets++;
	alarm(1);
}

void			set_rtt(double time)
{
	data.stats.rtt_total += time;
	data.stats.rtt_sqrsum += time * time;
	if (time < data.stats.rtt_min || data.stats.rtt_min == 0) {
		data.stats.rtt_min = time;
	}
	if (time > data.stats.rtt_max) {
		data.stats.rtt_max = time;
	}
}

void			recv_packet()
{
	int				ret = 0;
	double			time;
	struct timeval	recv_time;

	gettimeofday(&data.stats.start_time, NULL);
	ret = recvmsg(data.sock, &data.recv_msg, MSG_WAITALL|MSG_TRUNC);
	gettimeofday(&recv_time, NULL);
	if (ret < 0) {
		//TODO: do something i don't know what
	} else {
		data.stats.recv_packets++;
		time = get_time(data.send_hdr.time, recv_time);
		if (data.recv_hdr.icmp_hdr.type == 0) {
			char			paddr[INET_ADDRSTRLEN];
			int				ttl;

			ttl = get_ttl(data.recv_msg);
			inet_ntop(AF_INET, &data.src_addr->sin_addr, paddr, INET_ADDRSTRLEN);
			set_rtt(time);
			printf("%i bytes from %s: icmp_seq=%i ttl=%i time=%.3f ms\n", ret, paddr, data.recv_hdr.icmp_hdr.un.echo.sequence, ttl, time);
		} else {
			printf("Type: %i\n", data.recv_hdr.icmp_hdr.type);
		}
	}
}

double			get_mdev()
{
	double mdev;
	double avgsqr;

	avgsqr = data.stats.rtt_avg * data.stats.rtt_avg;
	mdev = (1. / data.stats.tran_packets) * data.stats.rtt_sqrsum - avgsqr;
	return sqrt(mdev);
}

void			int_handler(int signal)
{
	float	time;

	data.stats.rtt_avg = data.stats.rtt_total / data.stats.tran_packets;
	data.stats.rtt_mdev = get_mdev();
	printf("\n--- %s ping statistics ---\n", data.stats.addr);
	printf("%i packets transmitted, %i received, %.0f%% packet loss, time %.3fms\n", data.stats.tran_packets, data.stats.recv_packets, (double)(data.stats.tran_packets - data.stats.recv_packets) / data.stats.tran_packets * 100, data.stats.time);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", data.stats.rtt_min, data.stats.rtt_avg, data.stats.rtt_max, data.stats.rtt_mdev);
	exit(EXIT_SUCCESS);
}

void			alrm_handler(int signal)
{
	send_packet();
}

int				main(int argc, const char *argv[])
{
	struct	addrinfo *ainfo;

	signal(SIGINT, int_handler);
	signal(SIGALRM, alrm_handler);

	if (argc > 2 || argc < 1) {
		printf("Usage: ping {destination}\n");
		exit(EXIT_FAILURE);
	}
	ainfo = get_destination(argv[1]);
	if (ainfo == NULL) {
		printf("ping: %s: Name or service not known\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	set_socket(ainfo);
	send_packet();
	while (1) {
		recv_packet();
	}
	freeaddrinfo(ainfo);
	return 0;
}

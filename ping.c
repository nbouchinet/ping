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
	char	recv_data[INET_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	getaddrinfo(src, 0, &hints, &res);

	inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, recv_data, INET_ADDRSTRLEN);
	printf("PING %s (%s) %i(%i) bytes of data.\n", src, recv_data, PACKET_SIZE, PACKET_SIZE + IP_HEADER_SIZE + ECHO_REQUEST_SIZE);

	return res;
}

typedef struct t_send_hdr
{
	struct icmphdr	icmp_hdr;
	struct timeval	time;
}__attribute__((packed, aligned(64))) s_send_hdr;

struct t_send_hdr	get_dgram(struct addrinfo *ainfo)
{
	struct t_send_hdr send_hdr;
	struct sockaddr_in	*addr;

	addr = (struct sockaddr_in*)ainfo->ai_addr;
	memset(&send_hdr.icmp_hdr, 0, sizeof(send_hdr.icmp_hdr));
	send_hdr.icmp_hdr.type = ICMP_ECHO;
	send_hdr.icmp_hdr.un.echo.id = 1243;
	gettimeofday(&send_hdr.time, NULL);

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

void			send_dgram(struct addrinfo *ainfo)
{
	struct t_send_hdr	send_hdr;
	struct t_send_hdr	recv_hdr;
	struct msghdr		recv_msg;
	struct iovec		recv_vec;
	struct sockaddr_in	*src_addr;
	int					sock;

	uint8_t ctrlDataBuffer[CMSG_SPACE(sizeof(uint8_t))];

	src_addr = (struct sockaddr_in*)ainfo->ai_addr;

	recv_vec.iov_base = &recv_hdr;
	recv_vec.iov_len = sizeof(recv_hdr);

	memset(&recv_msg, 0, sizeof(recv_msg));
	recv_msg.msg_iov = &recv_vec;
	recv_msg.msg_iovlen = 1;
	recv_msg.msg_name = src_addr;
	recv_msg.msg_namelen = sizeof(*src_addr);
	recv_msg.msg_control = ctrlDataBuffer;
	recv_msg.msg_controllen = sizeof(ctrlDataBuffer);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	setsockopts(sock);
	if (sock < 0) {
		perror("socket");
	}

	while (1) {
		int				ret = 0;

		send_hdr = get_dgram(ainfo);
		send_hdr.icmp_hdr.un.echo.sequence++;
		if (sendto(sock, &send_hdr, sizeof(send_hdr), 0, (struct sockaddr*)src_addr, sizeof(*src_addr)) < 0) {
			perror("sendto");
		}
		ret = recvmsg(sock, &recv_msg, MSG_WAITALL|MSG_TRUNC);
		if (ret < 0) {
			perror("recvmsg");
		}
		if (recv_hdr.icmp_hdr.type == 0) {
			// TODO: Modify to handle more cleanly
			char			paddr[INET_ADDRSTRLEN];
			struct timeval	recv_time;

			int ttl = -1;
			struct cmsghdr * cmsg = CMSG_FIRSTHDR(&recv_msg); 
			for (; cmsg; cmsg = CMSG_NXTHDR(&recv_msg, cmsg)) {
				if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
					uint8_t * ttlPtr = (uint8_t *)CMSG_DATA(cmsg);
					ttl = *ttlPtr;
					break;
				}
			}

			inet_ntop(AF_INET, &src_addr->sin_addr, paddr, INET_ADDRSTRLEN);
			gettimeofday(&recv_time, NULL);
			printf("%i bytes from %s: icmp_seq=%i ttl=%i time=%.2f ms\n", ret, paddr, recv_hdr.icmp_hdr.un.echo.sequence, ttl, (double)(recv_time.tv_usec - recv_hdr.time.tv_usec) / 1000);
		}
		sleep(1);
	}
}

int				main(int argc, const char *argv[])
{
	struct	addrinfo *ainfo;

	if (check_user()) {
		printf("User is not root!\n");
		exit(EXIT_FAILURE);
	}
	if (argc > 2 || argc < 1) {
		printf("Usage: ping {destination}\n");
		exit(EXIT_FAILURE);
	}
	ainfo = get_destination(argv[1]);
	send_dgram(ainfo);
	freeaddrinfo(ainfo);
	return 0;
}

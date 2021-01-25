#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h> //inet_addr
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#include "minecraft.h"

int epoll_fd;

enum client_state {HANDSHAKE, FORWARD};

const size_t MAX_BUF_SIZE = 10240;
struct buffer {
	unsigned char *data;
	size_t len;
};

struct client {
	int client_fd;
	int server_fd;

	enum client_state state;

	struct buffer c2sbuf, s2cbuf;
} clients[100];
int client_count = 0;

void mod_epoll(int fd, int events) {
	struct epoll_event ev;
	ev.data.fd = fd;
	ev.events = events;
	epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

int init_buff(struct buffer *buf) {
	buf->data = malloc(MAX_BUF_SIZE);
	if(buf->data == NULL) return -1;
	buf->len = 0;
	return 0;
}

int init_client(int sockfd) {
	const size_t cid = client_count ++;

	if(init_buff(&clients[cid].c2sbuf) < 0) {
		perror("init_client: Failed to allocate buffer for new client");
		client_count --;
		return -1;
	}

	if(init_buff(&clients[cid].s2cbuf) < 0) {
		perror("init_client: Failed to allocate buffer for new client");
		client_count --;
		return -1;
	}

	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = sockfd;
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &event)) {
		perror("init_client: epoll_ctl failed");
		client_count --;
		return -1;
	}

	clients[cid].client_fd = sockfd;
	clients[cid].state = HANDSHAKE;

	return cid;
}

void close_client(int cid) {
	free(clients[cid].c2sbuf.data);
	free(clients[cid].s2cbuf.data);

	close(clients[cid].client_fd);
	if(clients[cid].state == FORWARD) {
		close(clients[cid].server_fd);
	}

	// delete client, fill the hole with the last client
	clients[cid] = clients[client_count - 1];
	client_count --;
}

int start_listening(int port) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("Could not create socket");
		return 1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
	}

	struct sockaddr_in server;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if(bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("bind failed");
		return -1;
	}

	if(listen(sockfd, 5) == -1) {
		perror("listen failed");
		return 1;
	}

	return sockfd;
}

int drain(int fd, struct buffer *buf) {
	// TODO write in a while() until no data left or EAGAIN for better performance?

	if(buf->len == 0) {
		printf("BUG?: drain() got an empty buffer\n");
		mod_epoll(fd, EPOLLIN);
		return 0;
	}

	int res = send(fd, buf->data, buf->len, MSG_NOSIGNAL);
	//printf("drain: res=%d\n", res);

	if(res == -1) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			mod_epoll(fd, EPOLLIN | EPOLLOUT);
			return 0;
		}
		return -1;
	}

	buf->len -= res;
	if(buf->len == 0) {
		mod_epoll(fd, EPOLLIN);
		return 0;
	}

	if(res == 0) {
		mod_epoll(fd, EPOLLIN | EPOLLOUT);
		return 0;
	}

	mod_epoll(fd, EPOLLIN | EPOLLOUT);
	memcpy(buf->data, buf->data + res, buf->len);
	return 0;
}

void drain_c2s(int cid) {
	if(drain(clients[cid].server_fd, &clients[cid].c2sbuf) < 0) {
		close_client(cid);
	}
}

void drain_s2c(int cid) {
	if(drain(clients[cid].client_fd, &clients[cid].s2cbuf) < 0) {
		close_client(cid);
	}
}

void handshake(int cid) {
	//printf("handshake(%d)\n", cid);

	/*
	printf("Current bytes (%ld):\n", clients[cid].c2sbuf.len);
	for(size_t i = 0;i < clients[cid].c2sbuf.len;i ++) {
		printf("%.02x ", clients[cid].c2sbuf.data[i]);
	}
	puts("");
	*/

	int bytes_used;
	struct mcpacket_hdr hdr = parse_hdr(clients[cid].c2sbuf.data, clients[cid].c2sbuf.len, &bytes_used);

	if(bytes_used < 0) { // critical error
		printf("parse_hdr reported critical error! Closing client\n");
		close_client(cid);
		return;
	}
	if(bytes_used == 0) { // need more data
		puts("parse_hdr needs more data");
		return;
	}
	//printf(" pid=%d payloadlen=%ld bytes_used=%d\n", hdr.packetid, hdr.payloadlen, bytes_used);

	/*
	printf(" payload=");
	for(size_t i = 0;i < packet.payloadlen;i ++) {
		printf("%.02x ", packet.payload[i]);
	}
	puts("");
	*/

	if(hdr.packetid != 0x00) {
		printf("hdr.packetid should've been 0x00. Closing client\n");
		free(hdr.payload);
		close_client(cid);
		return;
	}

	char status = 0;
	struct mcpacket_handshake packet = parse_handshake(hdr.payload, hdr.payloadlen, &status);
	free(hdr.payload);

	if(status < 0) {
		printf("parse_handshake reported critical error! Closing client\n");
		close_client(cid);
		return;
	}

	printf("NEW FORWARD: ver=%d, next_state=%d, hostname=",
			packet.protocol_version, packet.next_state);
	for(int i = 0;i < packet.server_address_len;i ++) {
		printf("%c", packet.server_address[i]);
	}
	printf("\n");

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_fd < 0) {
		perror("Could not create new socket to forward data to. Closing client");
		close_client(cid);
		free(packet.server_address);
		return;
	}

	clients[cid].state = FORWARD;
	clients[cid].server_fd = server_fd;

	if(fcntl(server_fd, F_SETFL, O_NONBLOCK) < 0) {
		perror("Could not set O_NONBLOCK to server_fd socket");
		close_client(cid);
		free(packet.server_address);
		return;
	}

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(2001);
	free(packet.server_address);

	if(connect(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0 && errno != EINPROGRESS) {
		perror("Could not connect socket to server. Closing client");
		close_client(cid);
		return;
	}

	struct epoll_event ev;
	ev.data.fd = server_fd;
	ev.events = EPOLLIN;
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev)) {
		perror("handshake: epoll_ctl failed");
		close_client(cid);
		return;
	}

	drain_c2s(cid);
}

void handle_c2s(int cid) {
	//printf("handle_c2s(%d)\n", cid);
	int res = recv(clients[cid].client_fd,
			clients[cid].c2sbuf.data + clients[cid].c2sbuf.len,
			MAX_BUF_SIZE - clients[cid].c2sbuf.len, 0);

	if(res == 0) { // socket closed?
		int error = 0;
		socklen_t len = sizeof(error);

		if(getsockopt(clients[cid].server_fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
			perror("handle_c2s: getsockopt failed:");
			close_client(cid);
			return;
		}

		// TODO why are we getting res=0 if the socket is not closed?
		if(error == 0) { // ok, socket was not closed, for some reason we had 0 bytes to read
			return;
		}

		printf("handle_c2s: closing client %d with sockfd %d!\n", cid, clients[cid].client_fd);
		close_client(cid);
		return;
	}

	if(res == -1) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) return; // no data left
		perror("handle_c2s(): Could not read");
		close_client(cid);
		return;
	}

	// data was received successfully
	clients[cid].c2sbuf.len += res;

	if(clients[cid].state == FORWARD) {
		drain_c2s(cid);
	} else {
		handshake(cid);
	}
}

void handle_s2c(int cid) {
	int res = recv(clients[cid].server_fd,
			clients[cid].s2cbuf.data + clients[cid].s2cbuf.len,
			MAX_BUF_SIZE - clients[cid].s2cbuf.len, 0);

	if(res == 0) { // socket closed?
		int error = 0;
		socklen_t len = sizeof(error);

		if(getsockopt(clients[cid].server_fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
			perror("handle_s2c: getsockopt failed:");
			close_client(cid);
			return;
		}

		// TODO why are we getting res=0 if the socket is not closed?
		if(error == 0) { // ok, socket was not closed, for some reason we had 0 bytes to read
			return;
		}

		printf("handle_s2c: closing client %d with sockfd %d!\n", cid, clients[cid].client_fd);
		close_client(cid);
		return;
	}

	if(res == -1) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) return; // no data left
		perror("handle_s2c(): Could not read");
		close_client(cid);
		return;
	}

	// data was received successfully
	clients[cid].s2cbuf.len += res;

	drain_s2c(cid);
}

void accept_connection(int listen_sock_fd) {
	int c = sizeof(struct sockaddr_in);
	struct sockaddr_in client;
	// TODO read man accept - why is &c needed?
	int new_socket = accept(listen_sock_fd, (struct sockaddr *)&client, (socklen_t*)&c);
	if(new_socket < 0) {
		perror("accept_connection: accept() failed");
		return;
	}

	if(fcntl(new_socket, F_SETFL, O_NONBLOCK) == -1) {
		perror("accept_connection: failed to add O_NONBLOCK to socket with fcntl");
		close(new_socket);
		return;
	}

	int cid = init_client(new_socket);
	if(cid < 0) {
		close(new_socket);
		return;
	}
	printf("Added client: %d (fd=%d)\n", cid, new_socket);
}

int get_client_id_by_clientfd(int sockfd) {
	for(int i = 0;i < client_count;i ++) {
		if(clients[i].client_fd == sockfd) return i;
	}
	return -1;
}

int get_client_id_by_serverfd(int sockfd) {
	for(int i = 0;i < client_count;i ++) {
		if(clients[i].server_fd == sockfd) return i;
	}
	return -1;
}

int main(int argc , char *argv[])
{
	int listen_sock_fd = start_listening(25565);
	if(listen_sock_fd < 0) return 1;

	epoll_fd = epoll_create1(0);
	if(epoll_fd < 0) {
		perror("epoll_create1 failed");
		return 1;
	}

	struct epoll_event ev;
	ev.data.fd = listen_sock_fd;
	ev.events = EPOLLIN;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock_fd, &ev);

	printf("EPOLLIN=%d, EPOLLOUT=%d\n", EPOLLIN, EPOLLOUT);

	const int MAX_EVENTS = 10;
	struct epoll_event events[MAX_EVENTS];
	while(1) {
		int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if(event_count < 0) {
			perror("epoll_wait failed");
			continue;
		}

		for(int i = 0;i < event_count;i ++) {
			//printf("============== NEW EPOLL EVENT fd=%d, flags=%d ================\n", events[i].data.fd, events[i].events);
			int fd = events[i].data.fd;
			if(fd == listen_sock_fd) {
				accept_connection(listen_sock_fd);
				continue;
			}

			int client_id;

			client_id = get_client_id_by_clientfd(fd);
			if(client_id != -1) {
				if(events[i].events & EPOLLIN) {
					handle_c2s(client_id);
				}
				if(events[i].events & EPOLLOUT) {
					drain_s2c(client_id);
				}
				//printf("SEVERE: Got unknown epoll event(%d) for fd=%d, client_id=%d\n", events[i].events, fd, client_id);
				continue;
			}

			client_id = get_client_id_by_serverfd(fd);
			if(client_id != -1) {
				if(events[i].events & EPOLLIN) {
					handle_s2c(client_id);
				}
				if(events[i].events & EPOLLOUT) {
					drain_c2s(client_id);
				}
				//printf("SEVERE: Got unknown epoll event(%d) for fd=%d, client_id=%d\n", events[i].events, fd, client_id);
				continue;
			}

			printf("CRITICAL: Received event for fd that could not be found in clients\n");
		}
	}

	return 0;
}


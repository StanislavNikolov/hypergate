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
#include "log/src/log.h"

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
		log_debug("BUG?: drain() got an empty buffer");
		mod_epoll(fd, EPOLLIN);
		return 0;
	}
	if(buf->len == MAX_BUF_SIZE) {
		log_debug("fd=%d buffer is full. Consider upping MAX_BUF_SIZE=%ld", fd, MAX_BUF_SIZE);
	}

	int res = send(fd, buf->data, buf->len, MSG_NOSIGNAL);

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
	log_trace("drain_s2c(%d)", cid);

	if(drain(clients[cid].server_fd, &clients[cid].c2sbuf) < 0) {
		log_trace("drain() failed, closing client");
		close_client(cid);
	}
}

void drain_s2c(int cid) {
	log_trace("drain_s2c(%d)", cid);

	if(drain(clients[cid].client_fd, &clients[cid].s2cbuf) < 0) {
		log_trace("drain() failed, closing client");
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
		log_warn("parse_hdr reported critical error! Closing client");
		close_client(cid);
		return;
	}
	if(bytes_used == 0) { // need more data
		log_trace("parse_hdr needs more data");
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
		log_warn("hdr.packetid should've been 0x00. Closing client");
		free(hdr.payload);
		close_client(cid);
		return;
	}

	char status = 0;
	struct mcpacket_handshake packet = parse_handshake(hdr.payload, hdr.payloadlen, &status);
	free(hdr.payload);

	if(status < 0) {
		log_warn("parse_handshake reported critical error! Closing client");
		close_client(cid);
		return;
	}

	log_info("NEW FORWARD: ver=%d, next_state=%d", packet.protocol_version, packet.next_state);

	printf("hostname=");
	for(int i = 0;i < packet.server_address_len;i ++) {
		printf("%c", packet.server_address[i]);
	}
	printf("\n");

	int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if(server_fd < 0) {
		perror("Could not create new socket to forward data to. Closing client");
		close_client(cid);
		free(packet.server_address);
		return;
	}

	clients[cid].state = FORWARD;
	clients[cid].server_fd = server_fd;

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

void debug(int cid) {
	printf("debug(%d)\n", cid);
	printf(" state=%d\n", clients[cid].state);
	printf(" c2sbuf.len=%ld\n", clients[cid].c2sbuf.len);
	printf(" s2cbuf.len=%ld\n", clients[cid].s2cbuf.len);
}


void handle_c2s(int cid) {
	log_trace("cid = %d", cid);

	int res = recv(clients[cid].client_fd,
			clients[cid].c2sbuf.data + clients[cid].c2sbuf.len,
			MAX_BUF_SIZE - clients[cid].c2sbuf.len, 0);

	if(res == 0) { // socket closed?
		log_debug("closing client %d with sockfd %d!", cid, clients[cid].client_fd);
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

	//debug(cid);
	if(clients[cid].state == FORWARD) {
		drain_c2s(cid);
	} else {
		handshake(cid);
	}
}

void handle_s2c(int cid) {
	log_trace("handle_s2c(%d)", cid);

	int res = recv(clients[cid].server_fd,
			clients[cid].s2cbuf.data + clients[cid].s2cbuf.len,
			MAX_BUF_SIZE - clients[cid].s2cbuf.len, 0);

	if(res == 0) { // socket closed?
		log_debug("closing client %d with sockfd %d!", cid, clients[cid].client_fd);
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

	//debug(cid);
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
	log_debug("Added client: cid=%d fd=%d", cid, new_socket);
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

	log_set_level(LOG_DEBUG);
	log_info("Hypergate started");

	const int MAX_EVENTS = 9;
	struct epoll_event events[MAX_EVENTS];
	while(1) {
		int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if(event_count < 0) {
			perror("epoll_wait failed");
			continue;
		}

		for(int i = 0;i < event_count;i ++) {
			log_trace("============== NEW EPOLL EVENT fd=%d, flags=%d ================", events[i].data.fd, events[i].events);
			int fd = events[i].data.fd;
			if(fd == listen_sock_fd) {
				accept_connection(listen_sock_fd);
				continue;
			}

			int client_id;

			client_id = get_client_id_by_clientfd(fd);
			if(client_id != -1) {
				//debug(client_id);
				if(events[i].events & EPOLLIN) {
					handle_c2s(client_id);
				}
				if(events[i].events & EPOLLOUT) {
					drain_s2c(client_id);
				}
				continue;
			}

			client_id = get_client_id_by_serverfd(fd);
			if(client_id != -1) {
				//debug(client_id);
				if(events[i].events & EPOLLIN) {
					handle_s2c(client_id);
				}
				if(events[i].events & EPOLLOUT) {
					drain_c2s(client_id);
				}
				continue;
			}

			log_warn("Received event for fd that could not be found in clients");
		}
	}

	return 0;
}


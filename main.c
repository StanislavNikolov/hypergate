#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h> //inet_addr
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

int listen_sock_fd;
int epoll_fd;

const size_t MAX_BUF_SIZE = 1000;
enum client_state {HANDSHAKE, FORWARD};

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
struct client {
	int fd;
	enum client_state state;
	unsigned char *buff;
	size_t used_buff;
} clients[100];
int client_count = 0;

struct mcpacket_hdr {
	int packetid;
	size_t payloadlen;
	unsigned char *payload;
};

struct mcpacket_handshake {
	int protocol_version;
	int server_address_len;
	unsigned char *server_address;
	int server_port;
	int next_state;
};

int init_client(int sockfd) {
	const size_t cid = client_count ++;
	clients[cid].buff = malloc(MAX_BUF_SIZE);

	if(clients[cid].buff == NULL) {
		perror("Failed to allocate buffer for new client.");
		client_count --;
		return -1;
	}

	clients[cid].fd = sockfd;
	clients[cid].state = HANDSHAKE;
	clients[cid].used_buff = 0;

	return cid;
}

void close_client(int cid) {
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, clients[cid].fd, NULL);
	close(clients[cid].fd);
	free(clients[cid].buff);

	// delete client, fill the hole with the last client
	clients[cid] = clients[client_count - 1];
	client_count --;
}

int start_listening(int port) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		puts("Could not create socket");
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

	puts("Bind done");

	return sockfd;
}

int read_VarInt(unsigned char *buf, size_t len, int *used) {
	int numRead = 0;
	int result = 0;
	unsigned char read;
	do {
		if(numRead == len) {
			*used = -1;
			return 0;
		}
		read = buf[numRead];
		int value = (read & 0b01111111);
		result |= (value << (7 * numRead));

		numRead++;
		if (numRead > 5) {
			*used = -2;
			return 0;
		}
	} while ((read & 0b10000000) != 0);

	*used = numRead;
	return result;
}

struct mcpacket_handshake parse_handshake(unsigned char *buf, size_t len, char *status) {
	struct mcpacket_handshake packet;

	int head = 0;
	int used = 0;

	packet.protocol_version = read_VarInt(buf + head, len - head, &used);
	if(used < 0) { *status = -1; return packet; }
	head += used;


	packet.server_address_len = read_VarInt(buf + head, len - head, &used);
	if(used < 0) { *status = -1; return packet; }
	head += used;


	if(packet.server_address_len > 255*4+3)    { *status = -1; return packet; }
	if(head + packet.server_address_len > len) { *status = -1; return packet; }
	packet.server_address = malloc(packet.server_address_len);
	if(packet.server_address == NULL)          { *status = -1; return packet; }
	memcpy(packet.server_address, buf + head, packet.server_address_len);
	head += packet.server_address_len;


	// server port - unsigned short, ignoring it
	if(head + 2 > len) {
		free(packet.server_address);
		*status = -1;
		return packet;
	}
	head += 2;


	packet.next_state = read_VarInt(buf + head, len - head, &used);
	if(used < 0) {
		free(packet.server_address);
		*status = -1;
		return packet;
	}


	*status = 0;
	return packet;
}

struct mcpacket_hdr parse_hdr(unsigned char *buf, size_t len, int *bytes_used) {
	struct mcpacket_hdr packet;

	int head = 0;
	int used = 0;

	// packet length, as in minectaft protocol - len of packetid + data
	int plen = read_VarInt(buf + head, len - head, &used);
	printf("parse_hdr, used=%d\n", used);
	if(used == -1) { // more data needed
		*bytes_used = 0;
		return packet;
	}
	if(used == -2) { // error reading plen
		*bytes_used = -1;
		return packet;
	}
	head += used;

	packet.packetid = read_VarInt(buf + head, len - head, &used);
	if(used == -1) { // more data needed
		*bytes_used = 0;
		return packet;
	}
	if(used == -2) { // error reading packetid
		*bytes_used = -1;
		return packet;
	}
	head += used;

	if(plen-used < 0) {
		*bytes_used = -1;
		return packet;
	}

	// payload = minecraft protocol "data"
	packet.payloadlen = plen-used;
	//printf("payloadlen=%d, head=%d, plen=%d, used=%d, len=%ld\n", packet.payloadlen, head, plen, used, len);
	if(head + packet.payloadlen > len) {
		*bytes_used = 0; // need more data
		return packet;
	}

	*bytes_used = head + packet.payloadlen;
	packet.payload = malloc(packet.payloadlen); // TODO error checking
	memcpy(packet.payload, buf + head, packet.payloadlen);

	return packet;
}

void handle(int cid) {
	int res = recv(clients[cid].fd, clients[cid].buff + clients[cid].used_buff, MAX_BUF_SIZE - clients[cid].used_buff, 0);
	//printf("recv %d new bytes\n", res);

	if(res == 0) { // socket closed
		printf("closing client %d with sockfd %d!\n", cid, clients[cid].fd);
		close_client(cid);
		return;
	}

	if(res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return; // no data left

	// data was received successfully
	clients[cid].used_buff += res;

	if(clients[cid].state == FORWARD) {
		// TODO simply forward the data to the real server
		return;
	}

	printf("Current bytes (%ld):\n", clients[cid].used_buff);
	for(size_t i = 0;i < clients[cid].used_buff;i ++) {
		printf("%.02x ", clients[cid].buff[i]);
	}
	puts("");

	int bytes_used;
	struct mcpacket_hdr hdr = parse_hdr(clients[cid].buff, clients[cid].used_buff, &bytes_used);
	//printf(" pid=%d payloadlen=%ld bytes_used=%d\n", hdr.packetid, hdr.payloadlen, bytes_used);

	if(bytes_used < 0) { // critical error
		printf("parse_hdr reported critical error! Closing client\n");
		close_client(cid);
		return;
	}
	if(bytes_used == 0) { // need more data
		puts("parse_hdr needs more data");
		return;
	}
	printf(" pid=%d payloadlen=%ld bytes_used=%d\n", hdr.packetid, hdr.payloadlen, bytes_used);

	// remove packet from client buffer
	memcpy(clients[cid].buff, clients[cid].buff + bytes_used, bytes_used);
	clients[cid].used_buff -= bytes_used;

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
	if(status < 0) {
		printf("parse_handshake reported critical error! Closing client\n");
		free(hdr.payload);
		close_client(cid);
		return;
	}

	printf("NEW FORWARD: ver=%d, next_state=%d, hlen=%d hostname=",
			packet.protocol_version, packet.next_state, packet.server_address_len);
	for(int i = 0;i < packet.server_address_len;i ++) {
		printf("%c", packet.server_address[i]);
	}
	printf("\n");

	free(packet.server_address);
	free(hdr.payload);
	// TODO set state forward

	//puts("handle done");
}

void *accept_connections() {
	puts("Waiting for connections");
	while(1) {
		int c = sizeof(struct sockaddr_in);
		struct sockaddr_in client;
		// TODO read man accept - why is &c needed?
		int new_socket = accept(listen_sock_fd, (struct sockaddr *)&client, (socklen_t*)&c);
		if(new_socket < 0) {
			perror("accept failed");
			continue;
		}

		fcntl(new_socket, F_SETFL, O_NONBLOCK);

		pthread_mutex_lock(&clients_mutex);

		printf("Adding client: %d\n", new_socket);
		int cid = init_client(new_socket);
		if(cid < 0) {
			close(new_socket);
		} else {
			struct epoll_event event;
			event.events = EPOLLIN;
			event.data.fd = new_socket;
			if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_socket, &event)) {
				perror("epoll_ctl failed");
				close_client(cid);
			}
		}

		pthread_mutex_unlock(&clients_mutex);
	}
}

int get_client_id_by_sockfd(int sockfd) {
	for(int i = 0;i < client_count;i ++) {
		if(clients[i].fd == sockfd) return i;
	}
	return -1;
}

int main(int argc , char *argv[])
{
	listen_sock_fd = start_listening(25565);
	if(listen_sock_fd < 0) {
		return 1;
	}

	listen(listen_sock_fd, 5);

	epoll_fd = epoll_create1(0);
	if(epoll_fd < 0) {
		perror("epoll_create1 failed");
		return 1;
	}

	pthread_t acc_thread;
	if(pthread_create(&acc_thread, NULL, accept_connections, NULL)) {
		perror("Failed to start listener thread");
		return 1;
	}

	const int MAX_EVENTS = 10;
	struct epoll_event events[MAX_EVENTS];
	while(1) {
		int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if(event_count < 0) {
			perror("epoll_wait failed");
			return 2;
		}

		pthread_mutex_lock(&clients_mutex);
		for(int i = 0;i < event_count;i ++) {
			int fd = events[i].data.fd;
			puts("==============");
			//printf("Got event for fd: %d\n", fd);
			handle(get_client_id_by_sockfd(fd));
		}
		pthread_mutex_unlock(&clients_mutex);
	}

	return 0;
}

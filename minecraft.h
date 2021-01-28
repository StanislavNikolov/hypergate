#include <stddef.h>

struct mcpacket_hdr {
	int packetid;
	size_t payloadlen;
	unsigned char *payload;
};

struct mcpacket_handshake {
	int protocol_version;
	//int server_address_len;
	char *server_address;
	int server_port;
	int next_state;
};

int read_VarInt(unsigned char *buf, size_t len, int *used);
struct mcpacket_handshake parse_handshake(unsigned char *buf, size_t len, char *status);
struct mcpacket_hdr parse_hdr(unsigned char *buf, size_t len, int *bytes_used);

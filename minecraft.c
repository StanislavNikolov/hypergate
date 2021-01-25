#include "minecraft.h"

#include <string.h>
#include <stdlib.h>

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

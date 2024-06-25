#include "selector.h"
#include "smtp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_ADDR_BUFFER 128
#define MAXSTRINGLENGTH 64

#define AUTH_ERROR 0x01
#define INVALID_VERSION 0x02
#define INVALID_COMMAND 0x03
#define INVALID_REQUEST 0x04
#define UNEXPECTED_ERROR 0x05

static char addrBuffer[MAX_ADDR_BUFFER];

void sendError(int fd, uint8_t error, __CONST_SOCKADDR_ARG addr,
			   socklen_t addr_len, const uint8_t ids[]);

int printSocketAddress(const struct sockaddr *address, char *addrBuffer) {
	void *numericAddress;

	in_port_t port;

	switch (address->sa_family) {
		case AF_INET:
			numericAddress = &((struct sockaddr_in *) address)->sin_addr;
			port = ntohs(((struct sockaddr_in *) address)->sin_port);
			break;
		case AF_INET6:
			numericAddress = &((struct sockaddr_in6 *) address)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *) address)->sin6_port);
			break;
		default:
			strcpy(addrBuffer, "[unknown type]");  // Unhandled type
			return 0;
	}
	// Convert binary to printable address
	if (inet_ntop(address->sa_family, numericAddress, addrBuffer, INET6_ADDRSTRLEN) == NULL)
		strcpy(addrBuffer, "[invalid address]");
	else {
		if (port != 0)
			sprintf(addrBuffer + strlen(addrBuffer), ":%u", port);
	}
	return 1;
}

#define DATAGRAM_LENGTH 14
#define PASS_LENGTH     8

void mng_passive_accept(struct selector_key *key) {

	struct sockaddr_storage clntAddr;  // Client address
	// Set Length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Block until receive message from a client
	uint8_t datagram[DATAGRAM_LENGTH];

	errno = 0;
	// Como alternativa a recvfrom se puede usar recvmsg, que es mas completa, por ejemplo permite saber
	// si el mensaje recibido es de mayor longitud a MAXSTRINGLENGTH

	ssize_t numBytesRcvd = recvfrom(key->fd, datagram, DATAGRAM_LENGTH, MSG_NOSIGNAL, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (numBytesRcvd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		fprintf(stderr, "recvfrom() failed: %s ", strerror(errno));
		return;
	}

	if (numBytesRcvd <= 0) {
		return;
	}

	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	fprintf(stdout, "Handling client %s, received %zu bytes\n", addrBuffer, numBytesRcvd);

	// TODO: Process the received datagram and send a response
	if (datagram[0] != 0xFF || datagram[1] != 0xFE) {
		fprintf(stderr, "Invalid datagram received");
		return;
	}

	uint8_t ids[] = {datagram[3], datagram[4]};

	if (datagram[2] != 0x00) {
		sendError(key->fd, INVALID_VERSION, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	uint8_t password[PASS_LENGTH];
	memcpy(password, datagram + 5, PASS_LENGTH);

	if (strncmp((char *) password, (char *)key->data, PASS_LENGTH) != 0) {
		sendError(key->fd, AUTH_ERROR, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	if (datagram[13] > 0x05) {
		sendError(key->fd, INVALID_COMMAND, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	uint8_t response_datagram[DATAGRAM_LENGTH] = {0};
	response_datagram[0] = 0xFF; // Protocol Signature
	response_datagram[1] = 0xFE; // Protocol Signature
	response_datagram[2] = 0x00; // Version
	response_datagram[3] = ids[0]; // Identif 1
	response_datagram[4] = ids[1]; // Identif 2
	response_datagram[5] = 0x00; // Status (0x00 = OK) (0x01 = Error)

	/*
	 * Si el comando fue 0x00, 0x01, 0x02
	 * La rta es un uint64_t (8 bytes) con la cantidad solicitada
	 *
	 * Si fue 0x03, 0x04, 0x05
	 * La rta es un booleando (1 byte) con el resultado de la operación
	 * 0x00 = TRUE  0x01 = FALSE
	 */

	if (datagram[13] == 0x00 || datagram[13] == 0x01 || datagram[13] == 0x02  || datagram[13] == 0x03) {

		struct status * stats = get_status();
		uint32_t value = 0;

		if (datagram[13] == 0x00)
			 value = stats->historic_connections;
		else if (datagram[13] == 0x01)
			value = stats->concurrent_connections;
		else if (datagram[13] == 0x02)
			value = stats->bytes_transfered;
		else if (datagram[13] == 0x03)
			value = stats->mails_sent;

		value = htonl(value);

		memcpy(response_datagram + 6, &value, sizeof(value));

	} else if (datagram[13] == 0x04 || datagram[13] == 0x05 || datagram[13] == 0x06) {
		response_datagram[6] = 0x00; // TODO
	}

	// Send the response back to the client
	ssize_t numBytesSent =
	    sendto(key->fd, response_datagram, DATAGRAM_LENGTH, 0, (struct sockaddr *) &clntAddr, sizeof(clntAddr));
	if (numBytesSent < 0) {
		fprintf(stderr, "sendto() failed");
	} else if (numBytesSent != numBytesRcvd) {
		fprintf(stderr, "sendto() sent unexpected number of bytes");
	}
}

void sendError(int fd, uint8_t error, __CONST_SOCKADDR_ARG addr,
			   socklen_t addr_len, const uint8_t ids[]) {
	uint8_t datagram[DATAGRAM_LENGTH] = {0};
	datagram[0] = 0xFF;
	datagram[1] = 0xFE;
	datagram[2] = 0x00;
	datagram[3] = ids[0];
	datagram[4] = ids[1];
	datagram[5] = error;

	ssize_t numBytesSent = sendto(fd, datagram, DATAGRAM_LENGTH, MSG_DONTWAIT, addr, addr_len);
	if (numBytesSent < 0) {
		fprintf(stderr, "sendto() failed with error: %s", strerror(errno));
	} else if (numBytesSent != DATAGRAM_LENGTH) {
		fprintf(stderr, "sendto() sent unexpected number of bytes");
	}
}

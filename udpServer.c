#include "mng.h"
#include "selector.h"
#include "smtp.h"
#include "utils.h"

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

static char addrBuffer[MAX_ADDR_BUFFER];

void send_error(int fd, uint8_t error, __CONST_SOCKADDR_ARG addr, socklen_t addr_len, const uint8_t ids[]);

void mng_passive_accept(struct selector_key *key) {
	struct sockaddr_storage clntAddr;  // Client address
	// Set Length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Block until receive message from a client
	uint8_t datagram[DATAGRAM_LENGTH];

	errno = 0;

	ssize_t numBytesRcvd =
	    recvfrom(key->fd, datagram, DATAGRAM_LENGTH, MSG_NOSIGNAL, (struct sockaddr *) &clntAddr, &clntAddrLen);
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
	if (datagram[i_PROT_SIGN_1] != PROTOCOL_SIGN_1 || datagram[i_PROT_SIGN_2] != PROTOCOL_SIGN_2) {
		fprintf(stderr, "Invalid datagram received");
		return;
	}

	uint8_t ids[] = {datagram[i_IDENTIF_1], datagram[i_IDENTIF_2]};

	if (datagram[2] != 0x00) {
		send_error(key->fd, INVALID_VERSION, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	uint8_t password[PASS_LENGTH];
	memcpy(password, datagram + 5, PASS_LENGTH);

	if (strncmp((char *) password, (char *) key->data, PASS_LENGTH) != 0) {
		send_error(key->fd, AUTH_ERROR, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	if (datagram[i_COMMAND] > MAX_COMMAND) {
		send_error(key->fd, INVALID_COMMAND, (struct sockaddr *) &clntAddr, sizeof(clntAddr), ids);
		return;
	}

	uint8_t response_datagram[DATAGRAM_LENGTH] = {0};
	response_datagram[i_PROT_SIGN_1] = PROTOCOL_SIGN_1;  // Protocol Signature
	response_datagram[i_PROT_SIGN_2] = PROTOCOL_SIGN_2;  // Protocol Signature
	response_datagram[i_VERSION] = PROTOCOL_VERSION;     // Version
	response_datagram[i_IDENTIF_1] = ids[0];             // Identif 1
	response_datagram[i_IDENTIF_2] = ids[1];             // Identif 2
	response_datagram[i_STATUS] = STATUS_OK;             // Status (0x00 = OK)

	struct status *stats = get_status();

	if (datagram[i_COMMAND] <= COM_MAILS) {
		uint32_t value = 0;

		if (datagram[i_COMMAND] == COM_HISTORIC)
			value = stats->historic_connections;
		else if (datagram[i_COMMAND] == COM_CONCURRENT)
			value = stats->concurrent_connections;
		else if (datagram[i_COMMAND] == COM_BYTES)
			value = stats->bytes_transfered;
		else if (datagram[i_COMMAND] == COM_MAILS)
			value = stats->mails_sent;

		value = htonl(value);

		memcpy(response_datagram + i_RES_OFFSET, &value, sizeof(value));

	} else if (datagram[i_COMMAND] == COM_TRANSFORM || datagram[i_COMMAND] == COM_ENABLE ||
	           datagram[i_COMMAND] == COM_DISABLE) {
		if (datagram[i_COMMAND] == COM_TRANSFORM) {
			response_datagram[i_RES_OFFSET] = stats->transformations ? RES_TRUE : RES_FALSE;
		} else if (datagram[i_COMMAND] == COM_ENABLE) {
			if (stats->program != NULL) {
				stats->transformations = true;
				response_datagram[i_RES_OFFSET] = RES_TRUE;
			} else {
				response_datagram[i_STATUS] = TRANSF_NOT_DEFINED;
			}
		} else if (datagram[i_COMMAND] == COM_DISABLE) {
			stats->transformations = false;
			response_datagram[i_RES_OFFSET] = RES_TRUE;
		}
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

void send_error(int fd, uint8_t error, __CONST_SOCKADDR_ARG addr, socklen_t addr_len, const uint8_t ids[]) {
	uint8_t datagram[DATAGRAM_LENGTH] = {0};
	datagram[i_PROT_SIGN_1] = PROTOCOL_SIGN_1;
	datagram[i_PROT_SIGN_2] = PROTOCOL_SIGN_2;
	datagram[i_VERSION] = PROTOCOL_VERSION;
	datagram[i_IDENTIF_1] = ids[0];
	datagram[i_IDENTIF_2] = ids[1];
	datagram[i_STATUS] = error;

	ssize_t numBytesSent = sendto(fd, datagram, DATAGRAM_LENGTH, MSG_DONTWAIT, addr, addr_len);
	if (numBytesSent < 0) {
		fprintf(stderr, "sendto() failed with error: %s", strerror(errno));
	} else if (numBytesSent != DATAGRAM_LENGTH) {
		fprintf(stderr, "sendto() sent unexpected number of bytes");
	}
}

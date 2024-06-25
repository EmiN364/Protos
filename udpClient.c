#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include "mng.h"

int sockAddrsEqual(const struct sockaddr *addr1, const struct sockaddr *addr2) {
	if (addr1 == NULL || addr2 == NULL)
		return addr1 == addr2;
	if (addr1->sa_family != addr2->sa_family)
		return 0;
	if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *ipv4Addr1 = (struct sockaddr_in *) addr1;
		struct sockaddr_in *ipv4Addr2 = (struct sockaddr_in *) addr2;
		return ipv4Addr1->sin_addr.s_addr == ipv4Addr2->sin_addr.s_addr && ipv4Addr1->sin_port == ipv4Addr2->sin_port;
	}
	if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6Addr1 = (struct sockaddr_in6 *) addr1;
		struct sockaddr_in6 *ipv6Addr2 = (struct sockaddr_in6 *) addr2;
		return memcmp(&ipv6Addr1->sin6_addr, &ipv6Addr2->sin6_addr, sizeof(struct in6_addr)) == 0 &&
		       ipv6Addr1->sin6_port == ipv6Addr2->sin6_port;
	}
	return 0;
}

int udpClientSocket(const char *host, const char *service, struct addrinfo **servAddr) {
	// Pedimos solamente para UDP, pero puede ser IPv4 o IPv6
	struct addrinfo addrCriteria;
	memset(&addrCriteria, 0, sizeof(addrCriteria));
	addrCriteria.ai_family = AF_UNSPEC;      // Any address family
	addrCriteria.ai_socktype = SOCK_DGRAM;   // Only datagram sockets
	addrCriteria.ai_protocol = IPPROTO_UDP;  // Only UDP protocol

	// Tomamos la primera de la lista
	int rtnVal = getaddrinfo(host, service, &addrCriteria, servAddr);
	if (rtnVal != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(rtnVal));
		exit(ERROR_STATUS);
	}

	// Socket cliente UDP
	return socket(
	    (*servAddr)->ai_family, (*servAddr)->ai_socktype, (*servAddr)->ai_protocol);  // Socket descriptor for client
}

int main(int argc, char *argv[]) {
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <Server Address/Name> <Auth> <Server Port/Service> <Command>\n", argv[0]);

		// List of commands
		fprintf(stderr, "Commands:\n");
		fprintf(stderr, "\t0: Get historic connections\n");
		fprintf(stderr, "\t1: Get concurrent connections\n");
		fprintf(stderr, "\t2: Get bytes transfered\n");
		fprintf(stderr, "\t3: Get mails sent\n");
		fprintf(stderr, "\t4: Get transformations status\n");
		fprintf(stderr, "\t5: Enable transformations\n");
		fprintf(stderr, "\t6: Disable transformations\n");

		exit(ERROR_STATUS);
	}

	// A diferencia de TCP, guardamos a que IP/puerto se envia la data, para verificar
	// que la respuesta sea del mismo host
	struct addrinfo *servAddr;

	char *server = argv[1];
	char *password = argv[2];

	ssize_t passwordLen = strlen(password);
	if (passwordLen != 8) {
		fprintf(stderr, "Password must be 8 characters long\n");
		exit(ERROR_STATUS);
	}

	char *servPort = argv[3];

	char *command = argv[4];
	if (strlen(command) != 1 || command[0] < '0' || command[0] > (MAX_COMMAND + '0')) {
		fprintf(stderr, "Command must be between 0 and %d\n", MAX_COMMAND);
		exit(ERROR_STATUS);
	}

	errno = 0;
	int sock = udpClientSocket(server, servPort, &servAddr);
	if (sock < 0) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
	}

	srand(time(NULL));   // Initialization, should only be called once.

	uint8_t datagram[DATAGRAM_LENGTH];

	datagram[i_PROT_SIGN_1] = PROTOCOL_SIGN_1;
	datagram[i_PROT_SIGN_2] = PROTOCOL_SIGN_2;
	datagram[i_VERSION] = PROTOCOL_VERSION;
	datagram[i_IDENTIF_1] = rand();  // Random
	datagram[i_IDENTIF_2] = rand();  // Random
	memcpy(datagram + i_AUTH, password, passwordLen);
	datagram[i_COMMAND] = command[0] - '0';  // comando

	// Enviamos el string, puede fallar si la length es mayor a la max de udp
	ssize_t numBytes = sendto(sock, datagram, sizeof(datagram), 0, servAddr->ai_addr, servAddr->ai_addrlen);
	if (numBytes < 0) {
		fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
		exit(ERROR_STATUS);
	}
	if (numBytes != sizeof(datagram)) {
		fprintf(stderr, "sendto() error, sent unexpected number of bytes\n");
		exit(ERROR_STATUS);
	}

	// Guardamos la direccion/puerto de respuesta para verificar que coincida con el servidor
	struct sockaddr_storage fromAddr;  // Source address of server
	socklen_t fromAddrLen = sizeof(fromAddr);

	// Establecemos un timeout de 5 segundos para la respuesta
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
	}

	uint8_t response_datagram[14];

	numBytes =
	    recvfrom(sock, response_datagram, sizeof(response_datagram), 0, (struct sockaddr *) &fromAddr, &fromAddrLen);
	if (numBytes < 0) {
		fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
		exit(ERROR_STATUS);
	} else {
		if (numBytes != sizeof(response_datagram))
			fprintf(stderr,
			        "recvfrom() error. Received unexpected number of bytes, expected:%zu received:%zu \n",
			        sizeof(response_datagram),
			        numBytes);

		// "Autenticamos" la respuesta
		if (!sockAddrsEqual(servAddr->ai_addr, (struct sockaddr *) &fromAddr))
			fprintf(stderr, "recvfrom() received a packet from other source\n");
	}

	if (response_datagram[i_PROT_SIGN_1] != PROTOCOL_SIGN_1 || response_datagram[i_PROT_SIGN_2] != PROTOCOL_SIGN_2) {
		fprintf(stderr, "Invalid protocol signature\n");
		exit(ERROR_STATUS);
	}

	if (response_datagram[i_VERSION] != PROTOCOL_VERSION) {
		fprintf(stderr, "Invalid protocol version\n");
		exit(ERROR_STATUS);
	}

	uint16_t identifier = (response_datagram[i_IDENTIF_1] << 8) | response_datagram[i_IDENTIF_2];
	uint8_t status = response_datagram[i_STATUS];

	if (status == STATUS_OK) {
		uint32_t count = 0;
		memcpy(&count, response_datagram + i_RES_OFFSET, sizeof(uint32_t));
		count = ntohl(count);

		printf("Identifier: %d\n", identifier);

		if (datagram[i_COMMAND] == COM_HISTORIC)
			printf("Historic connections: %u\n", count);
		else if (datagram[i_COMMAND] == COM_CONCURRENT)
			printf("Concurrent connections: %u\n", count);
		else if (datagram[i_COMMAND] == COM_BYTES)
			printf("Bytes transfered: %u\n", count);
		else if (datagram[i_COMMAND] == COM_MAILS)
			printf("Mails sent: %u\n", count);
		else if (datagram[i_COMMAND] == COM_TRANSFORM)
			printf("Transformations: %s\n", response_datagram[6] == 0x00 ? "enabled" : "disabled");
		else if (datagram[i_COMMAND] == COM_ENABLE)
			printf("Transformations enabled\n");
		else if (datagram[i_COMMAND] == COM_DISABLE)
			printf("Transformations disabled\n");
	} else {
		fprintf(stderr, "Error: ");
		switch (status) {
			case AUTH_ERROR:
				fprintf(stderr, "Auth failed\n");
				break;
			case INVALID_VERSION:
				fprintf(stderr, "Invalid version\n");
				break;
			case INVALID_COMMAND:
				fprintf(stderr, "Invalid command\n");
				break;
			case INVALID_REQUEST:
				fprintf(stderr, "Invalid request (length)\n");
				break;
			case TRANSF_NOT_DEFINED:
				fprintf(stderr, "Transformation program not defined\n");
				break;
			case UNEXPECTED_ERROR:
				fprintf(stderr, "Unexpected error\n");
				break;
			default:
				fprintf(stderr, "Unknown error\n");
				break;
		}
	}

	freeaddrinfo(servAddr);
	close(sock);
	return 0;
}

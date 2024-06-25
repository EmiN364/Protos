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
// #include "logger.h"
// #include "util.h"

int sockAddrsEqual(const struct sockaddr *addr1, const struct sockaddr *addr2) {
	if (addr1 == NULL || addr2 == NULL)
		return addr1 == addr2;
	else if (addr1->sa_family != addr2->sa_family)
		return 0;
	else if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *ipv4Addr1 = (struct sockaddr_in *) addr1;
		struct sockaddr_in *ipv4Addr2 = (struct sockaddr_in *) addr2;
		return ipv4Addr1->sin_addr.s_addr == ipv4Addr2->sin_addr.s_addr && ipv4Addr1->sin_port == ipv4Addr2->sin_port;
	} else if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6Addr1 = (struct sockaddr_in6 *) addr1;
		struct sockaddr_in6 *ipv6Addr2 = (struct sockaddr_in6 *) addr2;
		return memcmp(&ipv6Addr1->sin6_addr, &ipv6Addr2->sin6_addr, sizeof(struct in6_addr)) == 0 &&
		       ipv6Addr1->sin6_port == ipv6Addr2->sin6_port;
	} else
		return 0;
}

/* En esta version no iteramos por las posibles IPs del servidor Echo, como se hizo para TCP
** Realizar las modificaciones necesarias para que intente por todas las IPs
*/
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
		fprintf(stderr, "getaddrinfo() failed: %s", gai_strerror(rtnVal));
		exit(1);
	}

	// Como no es orientado a conexion y no nos intentamos conectar, confiamos en el primer addrinfo

	// Socket cliente UDP
	return socket(
	    (*servAddr)->ai_family, (*servAddr)->ai_socktype, (*servAddr)->ai_protocol);  // Socket descriptor for client
}

int main(int argc, char *argv[]) {
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <Server Address/Name> <Auth> <Server Port/Service> <Command>", argv[0]);
		exit(1);
	}

	// A diferencia de TCP, guardamos a que IP/puerto se envia la data, para verificar
	// que la respuesta sea del mismo host
	struct addrinfo *servAddr;

	char *server = argv[1];
	char *password = argv[2];

	ssize_t passwordLen = strlen(password);
	if (passwordLen != 8) {
		fprintf(stderr, "Password must be 10 characters long");
		exit(1);
	}

	char *servPort = argv[3];

	char *command = argv[4];

	errno = 0;
	int sock = udpClientSocket(server, servPort, &servAddr);
	if (sock < 0) {
		fprintf(stderr, "socket() failed: %s", strerror(errno));
	}

	srand(time(NULL));   // Initialization, should only be called once.

	uint8_t datagram[14];

	datagram[0] = 0xFF;
	datagram[1] = 0xFE;
	datagram[2] = 0x00;
	datagram[3] = rand();  // Random
	datagram[4] = rand();  // Random
	memcpy(datagram + 5, password, passwordLen);
	datagram[13] = command[0] - '0';  // comando

	// Enviamos el string, puede fallar si la length es mayor a la max de udp
	ssize_t numBytes = sendto(sock, datagram, sizeof(datagram), 0, servAddr->ai_addr, servAddr->ai_addrlen);
	if (numBytes < 0) {
		fprintf(stderr, "sendto() failed: %s", strerror(errno));
		exit(1);
	}
	if (numBytes != sizeof(datagram)) {
		fprintf(stderr, "sendto() error, sent unexpected number of bytes");
		exit(1);
	}

	// Guardamos la direccion/puerto de respuesta para verificar que coincida con el servidor
	struct sockaddr_storage fromAddr;  // Source address of server
	socklen_t fromAddrLen = sizeof(fromAddr);

	// Establecemos un timeout de 5 segundos para la respuesta
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "setsockopt error: %s", strerror(errno));
	}

	uint8_t response_datagram[14];

	numBytes =
	    recvfrom(sock, response_datagram, sizeof(response_datagram), 0, (struct sockaddr *) &fromAddr, &fromAddrLen);
	if (numBytes < 0) {
		fprintf(stderr, "recvfrom() failed: %s", strerror(errno));
	} else {
		if (numBytes != sizeof(response_datagram))
			fprintf(stderr,
			        "recvfrom() error. Received unexpected number of bytes, expected:%zu received:%zu ",
			        sizeof(response_datagram),
			        numBytes);

		// "Autenticamos" la respuesta
		if (!sockAddrsEqual(servAddr->ai_addr, (struct sockaddr *) &fromAddr))
			fprintf(stderr, "recvfrom() received a packet from other source");
	}

	if (response_datagram[0] != 0xFF || response_datagram[1] != 0xFE) {
		fprintf(stderr, "Invalid protocol signature");
		exit(1);
	}

	if (response_datagram[2] != 0x00) {
		fprintf(stderr, "Invalid protocol version");
		exit(1);
	}

	uint16_t identifier = (response_datagram[3] << 8) | response_datagram[4];
	uint8_t status = response_datagram[5];

	if (status == 0x00) {
		uint64_t count = 0;
		memcpy(&count, response_datagram + 6, sizeof(uint64_t));
		count = ntohl(count);
		printf("Identifier: %d\n", identifier);
		printf("Count: %lu\n", count);
		printf("Success: %s\n", status == 0x00 ? "TRUE" : "FALSE");
	} else {
		fprintf(stderr, "Error: ");
		switch (status) {
			case 0x01:
				fprintf(stderr, "Auth failed");
				break;
			case 0x02:
				fprintf(stderr, "Invalid version");
				break;
			case 0x03:
				fprintf(stderr, "Invalid command");
				break;
			case 0x04:
				fprintf(stderr, "Invalid request (length)");
				break;
			case 0x05:
				fprintf(stderr, "Unexpected error");
				break;
			default:
				fprintf(stderr, "Unknown error");
				break;
		}
	}

	freeaddrinfo(servAddr);
	close(sock);
	return 0;
}

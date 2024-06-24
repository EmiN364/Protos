#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define MAX_ADDR_BUFFER 128
#define MAXSTRINGLENGTH 64

static char addrBuffer[MAX_ADDR_BUFFER];

char *
printAddressPort(const struct addrinfo *aip, char addr[]) {
    char abuf[INET6_ADDRSTRLEN];
    const char *addrAux;
    if (aip->ai_family == AF_INET) {
        struct sockaddr_in *sinp;
        sinp = (struct sockaddr_in *) aip->ai_addr;
        addrAux = inet_ntop(AF_INET, &sinp->sin_addr, abuf, INET_ADDRSTRLEN);
        if (addrAux == NULL)
            addrAux = "unknown";
        strcpy(addr, addrAux);
        if (sinp->sin_port != 0) {
            sprintf(addr + strlen(addr), ": %d", ntohs(sinp->sin_port));
        }
    } else if (aip->ai_family == AF_INET6) {
        struct sockaddr_in6 *sinp;
        sinp = (struct sockaddr_in6 *) aip->ai_addr;
        addrAux = inet_ntop(AF_INET6, &sinp->sin6_addr, abuf, INET6_ADDRSTRLEN);
        if (addrAux == NULL)
            addrAux = "unknown";
        strcpy(addr, addrAux);
        if (sinp->sin6_port != 0)
            sprintf(addr + strlen(addr), ": %d", ntohs(sinp->sin6_port));
    } else
        strcpy(addr, "unknown");
    return addr;
}


int
printSocketAddress(const struct sockaddr *address, char *addrBuffer) {

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
            strcpy(addrBuffer, "[unknown type]");    // Unhandled type
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

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket UDP, para que escuche en cualquier IP, ya sea v4 o v6
 ** Funcion muy parecida a setupTCPServerSocket, solo cambia el tipo de servicio y que no es necesario invocar a listen()
 */
int setupUDPServerSocket(const char *service) {
    // Construct the server address structure
    struct addrinfo addrCriteria;                   // Criteria for address
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
    addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
    addrCriteria.ai_socktype = SOCK_DGRAM;          // Only datagram socket
    addrCriteria.ai_protocol = IPPROTO_UDP;         // Only UDP socket

    struct addrinfo *servAddr;            // List of server addresses
    int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s", gai_strerror(rtnVal));
        exit(1);
    }

    int servSock = -1;
    // Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
    // Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
    // Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
    for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
        errno = 0;
        // Create UDP socket
        servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (servSock < 0) {
            // log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
            fprintf(stdout, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
            continue;       // Socket creation failed; try next address
        }

        // Bind to ALL the address
        if (bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) {
            // Print local address of socket
            struct sockaddr_storage localAddr;
            socklen_t addrSize = sizeof(localAddr);
            if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
                printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
                // log(INFO, "Binding to %s", addrBuffer);
                fprintf(stdin, "Binding to %s", addrBuffer);
            }
        } else {
            // log(DEBUG, "Cant't bind %s", strerror(errno));
            fprintf(stdin, "Cant't bind %s", strerror(errno));
            close(servSock);  // Close and try with the next one
            servSock = -1;
        }
    }

    freeaddrinfo(servAddr);

    return servSock;
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "usage: %s <Server Port>\n", argv[0]);
        exit(1);
    }

    char *service = argv[1];    // First arg:  local port

    // Create socket for incoming connections
    int sock = setupUDPServerSocket(service);
    if (sock < 0) {
        fprintf(stderr, "socket() failed: %s ", strerror(errno));
        exit(1);
    }

    for (;;) {
        struct sockaddr_storage clntAddr;            // Client address
        // Set Length of client address structure (in-out parameter)
        socklen_t clntAddrLen = sizeof(clntAddr);

        // Block until receive message from a client
        char buffer[MAXSTRINGLENGTH];

        errno = 0;
        // Como alternativa a recvfrom se puede usar recvmsg, que es mas completa, por ejemplo permite saber
        // si el mensaje recibido es de mayor longitud a MAXSTRINGLENGTH

        // TODO: is it necessary to use the flag MSG_DONTWAIT to avoid blocking? Or because it's UDP it's not necessary?
        // ssize_t numBytesRcvd = recvfrom(sock, buffer, MAXSTRINGLENGTH, MSG_DONTWAIT, (struct sockaddr *) &clntAddr, &clntAddrLen);

        ssize_t numBytesRcvd = recvfrom(sock, buffer, MAXSTRINGLENGTH, 0, (struct sockaddr *) &clntAddr, &clntAddrLen);
        if (numBytesRcvd < 0) {
            fprintf(stderr, "recvfrom() failed: %s ", strerror(errno));
            continue;
        }

        printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
        fprintf(stdout, "Handling client %s, received %zu bytes", addrBuffer, numBytesRcvd);

        // TODO: Process the received datagram and send a response

        // Send the response back to the client
        ssize_t numBytesSent = sendto(sock, buffer, numBytesRcvd, 0, (struct sockaddr *) &clntAddr, sizeof(clntAddr));
        if (numBytesSent < 0) {
            fprintf(stderr, "sendto() failed");
        } else if (numBytesSent != numBytesRcvd) {
            fprintf(stderr, "sendto() sent unexpected number of bytes");
        }
    }
}

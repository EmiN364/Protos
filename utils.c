#include "utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define BASE_DIR "mails"

int is_valid_email(const char *email, bool is_mail_from) {
	int at_index = -1;
	int len = strlen(email);

	// Buscar la posición del '@'
	for (int i = 0; i < len; ++i) {
		if (email[i] == '@') {
			at_index = i;
			break;
		}
	}

	// si el @ está al inicio o al final, no es válido
	if (at_index == 0 || at_index == len - 1) {
		return 0;
	}

	// si el @ no está presente, puede ser valido el usuario
	if (at_index == -1) {
		char first_char = email[0];
		if (!((first_char >= 'a' && first_char <= 'z') || (first_char >= 'A' && first_char <= 'Z'))) {
			return 0;  // El primer carácter del usuario no es una letra
		}

		for (size_t i = 1; i < strlen(email); ++i) {
			char ch = email[i];
			if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' ||
			      ch == '_' || ch == '-')) {
				return 0;  // Caracter no válido en el usuario
			}
		}
		return at_index;  // Es válido
	}

	// Verificar que el dominio sea "pdc.com"
	if (!is_mail_from) {
		const char *expected_domain = "pdc.com";
		int domain_length = strlen(expected_domain);
		int domain_index = at_index + 1;  // Índice donde comienza el dominio

		for (int i = 0; i < domain_length; ++i) {
			if (email[domain_index + i] != expected_domain[i] && email[domain_index + i] != expected_domain[i] - 32) {
				return 0;  // Caracteres del dominio no coinciden (considerando mayúsculas y minúsculas)
			}
		}
	}

	// Verificar que el usuario cumpla con las reglas: ^[a-zA-Z][a-zA-Z0-9._-]*@
	char first_char = email[0];
	if (!((first_char >= 'a' && first_char <= 'z') || (first_char >= 'A' && first_char <= 'Z'))) {
		return 0;  // El primer carácter del usuario no es una letra
	}

	for (int i = 1; i < at_index; ++i) {
		char ch = email[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' ||
		      ch == '_' || ch == '-')) {
			return 0;  // Caracter no válido en el usuario
		}
	}

	return at_index;  // Es válido
}

int create_directory(const char *path) {
	struct stat st = {0};
	if (stat(path, &st) == -1) {
		if (mkdir(path, 0755) != 0) {
			perror("mkdir failed");
			return -1;
		}
	}
	return 0;
}

int build_mail_dir(const char *user) {
	char user_dir[100];
	char cur_dir[110];
	char new_dir[110];
	char tmp_dir[110];

	// Create base directory
	if (create_directory(BASE_DIR) != 0) {
		return -1;
	}

	if (strlen(user) > 80)
		return -1;

	// Construct user directory paths
	snprintf(user_dir, sizeof(user_dir), "%s/%s", BASE_DIR, user);
	snprintf(cur_dir, sizeof(cur_dir), "%s/cur", user_dir);
	snprintf(new_dir, sizeof(new_dir), "%s/new", user_dir);
	snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", user_dir);

	// Create directories
	if (create_directory(user_dir) != 0) {
		return -1;
	}
	if (create_directory(cur_dir) != 0) {
		return -1;
	}
	if (create_directory(new_dir) != 0) {
		return -1;
	}
	if (create_directory(tmp_dir) != 0) {
		return -1;
	}

	return 0;
}

void generate_id(char *buffer) {
	const char caracteres[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const int num_caracteres = sizeof(caracteres) - 1;

	for (int i = 0; i < 9; i++) {
		buffer[i] = caracteres[rand() % num_caracteres];
	}
	buffer[9] = '\0';  // Asegurarse de que la cadena termine en '\0'
}

void concat_date(char * buffer) {
	char date_formatted[72];
	time_t rawtime;
	time(&rawtime);
	const struct tm *tm_info = localtime(&rawtime);
	strftime(date_formatted, sizeof(date_formatted), " %a %b %d %H:%M:%S %Y", tm_info);
	strcat(buffer, date_formatted);
	strcat(buffer, "\r\n");
}

int createPipe(int fildes[2]) {
	int ret = pipe(fildes);
	if (ret != 0) {
		perror("Error while creating pipe");
		exit(EXIT_FAILURE);
	}
	return ret;
}

int createFork() {
	int pid = fork();
	if (pid < 0) {
		perror("Error while creating slave");
		exit(EXIT_FAILURE);
	}
	return pid;
}

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

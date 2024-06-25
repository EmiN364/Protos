#ifndef PROTOS_UTILS_H
#define PROTOS_UTILS_H

#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

/*
 * Verifica si un email es válido.
 */
int is_valid_email(const char *email, bool is_mail_from);

int create_directory(const char *path);

int build_mail_dir(const char *user);

void generate_id(char *buffer);

void concat_date(char * buffer);

int createPipe(int fildes[2]);

int createFork();

int printSocketAddress(const struct sockaddr *address, char *addrBuffer);

#endif  // PROTOS_UTILS_H

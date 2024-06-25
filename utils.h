#ifndef PROTOS_UTILS_H
#define PROTOS_UTILS_H

/*
 * Verifica si un email es válido.
 */
int is_valid_email(const char *email);

int create_directory(const char *path);

int build_mail_dir(const char *user);

void generate_id(char *buffer);

#endif  // PROTOS_UTILS_H

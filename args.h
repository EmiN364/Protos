#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10

struct users {
    char *name;
    char *pass;
};

struct smtpargs {

    char *         mail_dir;

    char           *smtp_addr;
    unsigned short smtp_port;

    char *          mng_addr;
    unsigned short  mng_port;

    bool 		    transform_enabled;

    struct users    users[MAX_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void 
parse_args(const int argc, char **argv, struct smtpargs *args);

#endif


#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#define MAX_USERS 10

#include <stdbool.h>

struct smtpargs {
	char 			*mail_dir;
	unsigned short 	smtp_port;
	unsigned short 	mng_port;
	char 			*transformations;
	char 			*pass;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(const int argc, char **argv, struct smtpargs *args);

#endif

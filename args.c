#include "args.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#define PASS_LENGTH 8

static unsigned short port(const char *s) {
	char *end = 0;
	const long sl = strtol(s, &end, 10);

	if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
	    sl > USHRT_MAX) {
		fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
		exit(EXIT_FAILURE);
	}
	return sl;
}

static const char *pass(const char *s) {
	if (strlen(s) != PASS_LENGTH) {
		fprintf(stderr, "password should have %d characters\n", PASS_LENGTH);
		exit(EXIT_FAILURE);
	}
	return s;
}

static void version(void) {
	fprintf(stderr,
	        "smtp version 1.0\n"
	        "ITBA Protocolos de Comunicación 2024/1 -- Grupo 4\n"
	        "LICENCIA MIT\n");
}

static void usage(const char *progname) {
	fprintf(stderr,
	        "Usage: %s [OPTION]...\n"
	        "\n"
	        "   -h               Imprime la ayuda y termina.\n"
	        "   -p <SMTP port>  Puerto entrante conexiones SMTP.\n"
	        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
	        "   -u <pass>		 Contraseña de admin. Hasta 10.\n"
	        "   -T <program>     Prende las transformaciones.\n"
	        "   -v               Imprime información sobre la versión versión y termina.\n"
	        "\n\n",
	        progname);
	exit(EXIT_FAILURE);
}

void parse_args(const int argc, char **argv, struct smtpargs *args) {
	memset(args, 0, sizeof(*args));

	args->smtp_port = 2525;
	args->mng_port = 2626;
	args->pass = "secretpa";

	int c;

	while (true) {
		int option_index = 0;
		static struct option long_options[] = {
		    /* { "doh-ip",    required_argument, 0, 0xD001 },
		    { "doh-port",  required_argument, 0, 0xD002 },
		    { "doh-host",  required_argument, 0, 0xD003 },
		    { "doh-path",  required_argument, 0, 0xD004 },
		    { "doh-query", required_argument, 0, 0xD005 },*/
		    {0, 0, 0, 0}
        };

		c = getopt_long(argc, argv, "hT:p:P:u:v", long_options, &option_index);  // : significa que requiere argumento
		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'T':
				args->transformations = optarg;
				break;
			case 'p':
				args->smtp_port = port(optarg);
				break;
			case 'P':
				args->mng_port = port(optarg);
				break;
			case 'u':
				args->pass = (char *) pass(optarg);
				break;
			case 'v':
				version();
				exit(0);
				break;
			/*case 0xD001:
				args->doh.ip = optarg;
				break;
			case 0xD002:
				args->doh.port = port(optarg);
				break;
			case 0xD003:
				args->doh.host = optarg;
				break;
			case 0xD004:
				args->doh.path = optarg;
				break;
			case 0xD005:
				args->doh.query = optarg;
				break;*/
			default:
				fprintf(stderr, "unknown argument %d.\n", c);
				exit(EXIT_FAILURE);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "argument not accepted: ");
		while (optind < argc) {
			fprintf(stderr, "%s ", argv[optind++]);
		}
		fprintf(stderr, "\n");
		exit(EXIT_FAILURE);
	}
}

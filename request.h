#ifndef Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H
#define Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H

#include "buffer.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct request {
	char verb[10];
	char arg1[32];
};

enum request_state {
	request_verb,
	request_sep_arg1,
	request_arg1,

	request_cr,
	request_data,

	// apartir de aca están done
	request_done,

	// y apartir de aca son considerado con error
	request_error,
	/* request_error_unknown_verb,
	request_error_invalid_length, */

};

struct request_parser {
	struct request *request;
	enum request_state state;
	/** cuantos bytes ya leimos */
	uint8_t i;

	// opc. punteros a funcion / enum con comandos
};

/** inicializa el parser */
void request_parser_init(struct request_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum request_state request_parser_feed(struct request_parser *p, const uint8_t c);

/**
 * por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool request_is_done(const enum request_state st, bool *errored);

void request_close(struct request_parser *p);

#endif

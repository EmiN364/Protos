#ifndef Au9MTAsFSOTIW3GaVruXIl3gVBU_DATA_H
#define Au9MTAsFSOTIW3GaVruXIl3gVBU_DATA_H

#include "buffer.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

enum data_state {
	// Estoy leyendo data
	// '\r' -> data_cr, nop
	//  *   -> data_data, write(c)
	data_data,

	// Lei un CR
	// '\n' -> data_crlf, nop
	//  *   -> data_data, write('\r' + c)
	data_cr,

	// Lei un LF
	// '.' -> data_crlfdot, nop
	//  *   -> data_data, write('\r\n' + c)
	data_crlf,
	data_crlf_start,  // INICIAL

	// Lei un .
	// '\r' -> data_crlfdotcr, nop
	//  *   -> data_data, write('\r\n.' + c)
	data_crlfdot,

	// Lei un CR
	// '\n' -> data_done, nop
	//  *   -> data_data, write('\r\n.\r' + c)
	data_crlfdotcr,

	// apartir de aca están done
	//  *   -> data_done, nop
	data_done,  // Lei un LF, termine
};

struct data_parser {
	enum data_state state;

	buffer output_buffer;
	uint8_t raw_buffer[2048];

	// opc. punteros a funcion / enum con comandos
};

/** inicializa el parser */
void data_parser_init(struct data_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum data_state data_parser_feed(struct data_parser *p, uint8_t c);

/**
 * por cada elemento del buffer llama a `data_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum data_state data_consume(buffer *b, struct data_parser *p);

/**
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool data_is_done(enum data_state st);

void data_close(struct data_parser *p);

#endif

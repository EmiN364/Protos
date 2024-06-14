#include "smtp.h"

#include "buffer.h"
#include "request.h"
#include "stm.h"

#include <arpa/inet.h>
#include <assert.h>  // assert
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <time.h>
#include <unistd.h>  // close
#include <strings.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

/** obtiene el struct (smtp *) desde la llave de selección  */
#define ATTACHMENT(key) ((struct smtp *) (key)->data)

struct smtp {
	/** información del cliente */
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len;

	/** maquinas de estados */
	struct state_machine stm;

	/** parser */
	struct request request;
	struct request_parser request_parser;

	/** buffers */
	uint8_t raw_buff_read[2048], raw_buff_write[2048], raw_buff_file[2048];  // TODO: Fix this
	buffer read_buffer, write_buffer, file_buffer;

	bool is_data;

	char mailfrom[255];

	int fileFd;
	/*
	 * mailfrom
	 * lista receipients
	 */
};

struct status {
	int historic_connections, concurrent_connections, bytes_transfered, mails_sent;
};

struct status global_status = {0};

/** maquina de estados general */
enum smtpstate {
	/**
	 * enviar el mensaje `hello` al cliente
	 *
	 * Intereses:
	 *     - OP_WRITE sobre client_fd
	 *
	 * Transiciones:
	 *   - RESPONSE_WRITE  mientras queden bytes por enviar
	 *   - HELLO_WRITE     cuando se enviaron todos los bytes
	 *   - ERROR           ante cualquier error (IO/parseo)
	 */
	RESPONSE_WRITE,

	/**
	 * lee la respuesta del `hello' del cliente.
	 *
	 * Intereses:
	 *     - OP_READ sobre client_fd
	 *
	 * Transiciones:
	 *   - HELLO_WRITE  mientras el mensaje no esté completo
	 *   - REQUEST_READ cuando está completo
	 *   - ERROR        ante cualquier error (IO/parseo)
	 */
	REQUEST_READ,

	/**
	 * lee la data del cliente.
	 *
	 * Intereses:
	 *     - OP_READ sobre client_fd
	 *
	 */
	DATA_READ,

	/**
	 * escribe la data del cliente.
	 *
	 * Intereses:
	 *     - NOP 	   sobre client_fd
	 *     - OP_WRITE  sobre archivo_fd
	 *
	 * Transiciones:
	 *   - DATA_WRITE    mientras tenga cosas para escribir
	 *   - DATA_READ     cuando se me vacio el buffer
	 *   - ERROR         ante cualquier error (IO/parseo)
	 */
	// DATA_WRITE,

	// TODO: Add DATA_READ. A medida q voy leyendo voy escribiendo en el archivo
	// En caso de transform, en vez de escribir al archivo directo, escribimos a otro programa. Desp leemos
	// la salida de ese programa, y eso lo escribimos al archivo

	// estados terminales
	DONE,
	ERROR,
};

static void request_read_init(const unsigned state, struct selector_key *key) {
	struct request_parser* p = &ATTACHMENT(key)->request_parser;
	p->request = &ATTACHMENT(key)->request;
	request_parser_init(p);
}

static void request_read_close(const unsigned state, struct selector_key *key) {
	request_close(&ATTACHMENT(key)->request_parser);
}

static enum smtpstate request_process(struct smtp * state) {
	if (strcasecmp(state->request_parser.request->verb, "data") == 0) {
		state->is_data = true;
		return RESPONSE_WRITE;
	}

	if (strcasecmp(state->request_parser.request->verb, "mail from") == 0) {
		// TODO: Check arg1
		strcpy(state->mailfrom, state->request_parser.request->arg1);

		size_t count;
		uint8_t *ptr;

		// Generate response
		ptr = buffer_write_ptr(&state->write_buffer, &count);

		// TODO: Check count with n (min(n,count))
		strcpy((char *) ptr, "250 Ok\r\n");
		buffer_write_adv(&state->write_buffer, 8);

		return RESPONSE_WRITE;
	}
	if (strcasecmp(state->request_parser.request->verb, "ehlo") == 0) {
		/*
		 *  250-emilio
			250-PIPELINING
			250 SIZE 10240000
		 * */
		return RESPONSE_WRITE;
	}

	size_t count;
	uint8_t *ptr;

	// Generate response
	ptr = buffer_write_ptr(&state->write_buffer, &count);

	// TODO: Check count with n (min(n,count))
	strcpy((char *) ptr, "250 Ok\r\n");
	buffer_write_adv(&state->write_buffer, 8);

	return RESPONSE_WRITE;
}

static unsigned int request_read_posta(struct selector_key *key, struct smtp *state) {
	unsigned int ret = REQUEST_READ;;
	bool error = false;
	int st = request_consume(&state->read_buffer, &state->request_parser, &error);
	if (request_is_done(st, 0)) {
		if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
			// Procesamiento
			ret = request_process(state); // tengo todo completo
		} else {
			ret = ERROR;
		}
	}
	return ret;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned request_read(struct selector_key *key) {
	unsigned ret;
	struct smtp *state = ATTACHMENT(key);

	if (buffer_can_read(&state->read_buffer)) {
		ret = request_read_posta(key, state);
	} else {
		size_t count;
		uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
		ssize_t n = recv(key->fd, ptr, count, 0);

		if (n > 0) {
			buffer_write_adv(&state->read_buffer, n);
			ret = request_read_posta(key, state);
		} else {
			ret = ERROR;
		}
	}

	return ret;
}

static unsigned int data_read_posta(struct selector_key *key, struct smtp *state) {
	unsigned int ret = DATA_READ;
	bool error = false;

	enum data_state st = p->state;

	while(buffer_can_read(b)) {
		const uint8_t c = buffer_read(b);
		st = data_parser_feed(p, c);
		if(data_is_done(st, errored)) {
			break;
		}
	}

	struct selector_key key_file = {};

	// write to file from buffer if is not empty
	if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_NOOP)) {
		if (SELECTOR_SUCCESS == selector_set_interest_key(key_file, OP_WRITE))
			ret = DATA_WRITE; // Vuelvo a request_read

	} else {
		ret = ERROR;
	}

	return ret;
}

static unsigned data_read(struct selector_key *key) {
	unsigned ret;
	struct smtp *state = ATTACHMENT(key);

	if (buffer_can_read(&state->read_buffer)) {
		ret = data_read_posta(key, state);
	} else {
		size_t count;
		uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
		ssize_t n = recv(key->fd, ptr, count, 0);

		if (n > 0) {
			buffer_write_adv(&state->read_buffer, n);
			ret = data_read_posta(key, state);
		} else {
			ret = ERROR;
		}
	}

	return ret;
}

static void smtp_done(struct selector_key *key);

static unsigned response_write(struct selector_key *key) {
	unsigned ret = RESPONSE_WRITE;

	size_t count;
	buffer *wb = &ATTACHMENT(key)->write_buffer;

	uint8_t *ptr = buffer_read_ptr(wb, &count);
	ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

	if (n >= 0) {
		buffer_read_adv(wb, n);
		if (!buffer_can_read(wb)) {
			// TODO: Ver si voy para data o request
			if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
				ret = ATTACHMENT(key)->is_data ? DATA_READ : REQUEST_READ;
			} else {
				ret = ERROR;
			}
		}
	} else {
		ret = ERROR;
	}

	return ret;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
	     .state = RESPONSE_WRITE, /*
	     .on_arrival       = request_read_init,
	     .on_departure     = request_read_close,*/
	     .on_write_ready   = response_write,
    },
    {
	     .state = REQUEST_READ,
	     .on_arrival       = request_read_init,
	     .on_departure     = request_read_close,
	     .on_read_ready	   = request_read,
    },
    {
    	 .state = DATA_READ,
     	/*.on_arrival       = request_read_init, // TODO: Add init
        .on_departure     = request_read_close,*/
     	.on_read_ready	   = data_read,
 	},
    {
		.state = DONE,
    },
    {
		.state = ERROR,
    }
};

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void smtp_read(struct selector_key *key);
static void smtp_write(struct selector_key *key);
static void smtp_close(struct selector_key *key);
static const struct fd_handler smtp_handler = {
    .handle_read = smtp_read,
    .handle_write = smtp_write,
    .handle_close = smtp_close,
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.

static void smtp_read(struct selector_key *key) {
	struct state_machine *stm = &ATTACHMENT(key)->stm;
	const enum smtpstate st = stm_handler_read(stm, key);

	if (ERROR == st || DONE == st) {
		smtp_done(key);
	}
}

static void smtp_write(struct selector_key *key) {
	struct state_machine *stm = &ATTACHMENT(key)->stm;
	const enum smtpstate st = stm_handler_write(stm, key);

	if (ERROR == st || DONE == st) {
		smtp_done(key);
	} else if (REQUEST_READ == st || DATA_READ == st) {
		buffer *rb = &ATTACHMENT(key)->read_buffer;
		if (buffer_can_read(rb)) {
			smtp_read(key); // Si hay para leer en el buffer, sigo leyendo sin bloquearme
		}
	}
}

static void smtp_close(struct selector_key *key) {
	// socks5_destroy(ATTACHMENT(key));
}

static void smtp_done(struct selector_key *key) {
	if (key->fd != -1) {
		if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, key->fd)) {
			abort();
		}
		close(key->fd);
	}
}

static void smtp_destroy(struct smtp *state) {
	free(state);
}

/** Intenta aceptar la nueva conexión entrante*/
void smtp_passive_accept(struct selector_key *key) {
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	struct smtp *state = NULL;

	const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (client == -1) {
		goto fail;
	}
	if (selector_fd_set_nio(client) == -1) {
		goto fail;
	}
	state = malloc(sizeof(struct smtp));
	if (state == NULL) {
		// sin un estado, nos es imposible manejaro.
		// tal vez deberiamos apagar accept() hasta que detectemos
		// que se liberó alguna conexión.
		goto fail;
	}
	memset(state, 0, sizeof(*state));
	memcpy(&state->client_addr, &client_addr, client_addr_len);
	state->client_addr_len = client_addr_len;

	state->stm.initial = RESPONSE_WRITE;
	state->stm.max_state = ERROR;
	state->stm.states = client_statbl;
	stm_init(&state->stm);

	buffer_init(&state->read_buffer, N(state->raw_buff_read), state->raw_buff_read);
	buffer_init(&state->write_buffer, N(state->raw_buff_write), state->raw_buff_write);

	memcpy(&state->raw_buff_write, "Hola\n", 5);
	buffer_write_adv(&state->write_buffer, 5);

    state->request_parser.request = &state->request;
    request_parser_init(&state->request_parser);

	if (SELECTOR_SUCCESS != selector_register(key->s, client, &smtp_handler, OP_WRITE, state)) {
		goto fail;
	}
	return;
fail:
	if (client != -1) {
		close(client);
	}
	smtp_destroy(state);
}

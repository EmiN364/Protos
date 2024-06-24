#include "smtp.h"

#include "buffer.h"
#include "data.h"
#include "request.h"
#include "stm.h"

#include <arpa/inet.h>
#include <assert.h>  // assert
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <strings.h>
#include <time.h>
#include <unistd.h>  // close
#include <sys/stat.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(x,y) (x < y ? x : y)

#define BUFFER_LENGTH 2048
// TODO: Check this

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
	struct data_parser data_parser;

	/** buffers */
	uint8_t raw_buff_read[BUFFER_LENGTH], raw_buff_write[BUFFER_LENGTH];
	buffer read_buffer, write_buffer;

	bool is_data;

	char mailfrom[255];
	char rcpt[255]; // TODO: Change to list

	int file_fd;
	int socket_fd;
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
	DATA_WRITE,

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

static void data_read_init(struct selector_key *key) {
	struct data_parser* p = &ATTACHMENT(key)->data_parser;
	data_parser_init(p);
}

static void data_read_close(struct selector_key *key) {
	data_close(&ATTACHMENT(key)->data_parser);
}

static void file_write(struct selector_key *key) {
	struct state_machine *stm = &ATTACHMENT(key)->stm;
	const enum smtpstate st = stm_handler_write(stm, key);

	/*if (ERROR == st || DONE == st) {
		smtp_done(key);
	} else if (REQUEST_READ == st || DATA_READ == st) {
		buffer *rb = &ATTACHMENT(key)->read_buffer;
		if (buffer_can_read(rb)) {
			smtp_read(key); // Si hay para leer en el buffer, sigo leyendo sin bloquearme
		}
	}*/
}

static const struct fd_handler file_handler = {
	.handle_read = NULL,
	.handle_write = file_write,
	.handle_close = NULL,
};

static enum smtpstate request_process(struct selector_key *key, struct smtp * state) {

	char * response;
	enum smtpstate res_state = RESPONSE_WRITE;

	if (strcasecmp(state->request_parser.request->verb, "data") == 0) {
		if (state->mailfrom[0] == '\0' || state->rcpt[0] == '\0') {
			response = "503 5.5.1 Error: need RCPT command\r\n";
		} else {
			response = "354 End data with <CR><LF>.<CR><LF>\r\n";

			state->is_data = true;

			data_read_init(key);

			struct stat st = {0};

			/*"mails/" + state->rcpt*/
			char file_name[100] = "mails/";
			if (strlen(state->rcpt) > 90)
				return ERROR;

			strcat(file_name, state->rcpt);

			if (stat("mails", &st) == -1) {
				if (mkdir("mails", 0755) == -1) {
					perror("Error creating directory");
					return ERROR;
				}
			}

			// Init new file
			const int file = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
			if (file < 0)
				return ERROR;

			state->file_fd = file;
			state->socket_fd = key->fd;

			if (SELECTOR_SUCCESS != selector_register(key->s, file, &file_handler, OP_NOOP, state))
				return ERROR;

		}
	} else if (strcasecmp(state->request_parser.request->verb, "mail from") == 0) {
		// TODO: Check arg1
		strcpy(state->mailfrom, state->request_parser.request->arg1);
		response = "250 2.1.0 Ok\r\n";
	} else if (strcasecmp(state->request_parser.request->verb, "rcpt to") == 0) {
		if (state->mailfrom[0] == '\0') {
			response = "503 5.5.1 Error: need MAIL command\r\n";
		} else {
			// TODO: Check arg1
			strcpy(state->rcpt, state->request_parser.request->arg1);
			response = "250 2.1.5 Ok\r\n";
		}
	} else if (strcasecmp(state->request_parser.request->verb, "ehlo") == 0) {
		response = "250-localhost\n250-PIPELINING\n250 SIZE 10240000\r\n";
	} else if (strcasecmp(state->request_parser.request->verb, "helo") == 0) {
		response = "250 localhost\r\n";
	} else if (strcasecmp(state->request_parser.request->verb, "quit") == 0) {
		response = "221 2.0.0 Bye\r\n";
		res_state = DONE;
	} else if (state->request_parser.i > 0) {
		response = "502 5.5.2 Error: command not recognized\r\n";
	} else {
		response = "500 5.5.2 Error: bad syntax\r\n";
	}

	size_t count;
	uint8_t *ptr = buffer_write_ptr(&state->write_buffer, &count);

	const int len = MIN(count, strlen(response) + 1); // TODO: Check that all the response is in buffer
	strncpy((char *) ptr, response, len);
	buffer_write_adv(&state->write_buffer, len);

	return res_state;
}

static unsigned int request_read_posta(struct selector_key *key, struct smtp *state) {
	unsigned int ret = REQUEST_READ;;
	bool error = false;
	int st = request_consume(&state->read_buffer, &state->request_parser, &error);
	if (request_is_done(st, 0)) {
		if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
			// Procesamiento
			ret = request_process(key, state); // tengo todo completo
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
	unsigned int ret;

	buffer * b = &state->read_buffer;
	enum data_state st;

	while(buffer_can_read(b)) {
		const uint8_t c = buffer_read(b);
		st = data_parser_feed(&state->data_parser, c);
		// buffer_write(&state->file_buffer, c);
		if(data_is_done(st)) {
			break;
		}
	}

	if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_NOOP)) {
		if (SELECTOR_SUCCESS == selector_set_interest(key->s, state->file_fd, OP_WRITE))
			ret = DATA_WRITE;
		else
			ret = ERROR;
	} else {
		ret = ERROR;
	}

	/*
	struct selector_key key_file;

	// write to file from buffer if is not empty
	if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_NOOP)) {
		if (SELECTOR_SUCCESS == selector_set_interest_key(&key_file, OP_WRITE))
			ret = DATA_WRITE; // Desp Vuelvo a request_read
	} else {
		ret = ERROR;
	}
	*/

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

static unsigned data_write(struct selector_key *key) {
	unsigned ret = DATA_WRITE;

	size_t count;
	buffer *wb = &ATTACHMENT(key)->data_parser.output_buffer;
	struct smtp *state = ATTACHMENT(key);

	uint8_t *ptr = buffer_read_ptr(wb, &count);
	ssize_t n = write(key->fd, ptr, count);

	if (n >= 0) {
		buffer_read_adv(wb, n);
		if (!buffer_can_read(wb)) {
			if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP))
				ret = ERROR;
			else {
				if (state->data_parser.state == data_done) {
					if (SELECTOR_SUCCESS != selector_set_interest(key->s, state->socket_fd, OP_WRITE))
						ret = ERROR;
					else {
						state->is_data = false;

						close(state->file_fd);
						state->file_fd = 0;
						data_read_close(key);

						ptr = buffer_write_ptr(&state->write_buffer, &count);

						// TODO: Check that all the response is in buffer, and that 35 is correct or it should be 36
						const int len = MIN(36, count);
						strncpy((char *) ptr, "250 2.0.0 Ok: queued as 5E0AA44E8\n", len);
						buffer_write_adv(&state->write_buffer, len);

						ret = RESPONSE_WRITE;
					}
				} else {
					if (SELECTOR_SUCCESS != selector_set_interest(key->s, state->socket_fd, OP_READ))
						ret = ERROR;
					else
						ret = DATA_READ;
				}
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
	     .state = RESPONSE_WRITE,
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
     	/*.on_arrival       = data_read_init,
        .on_departure     = data_read_close,*/
     	.on_read_ready	   = data_read,
 	},
    {
    	 .state = DATA_WRITE,
        .on_write_ready	   = data_write,
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

static void smtp_destroy(struct smtp *state) {
	free(state);
}

static void smtp_close(struct selector_key *key) {
	smtp_destroy(ATTACHMENT(key));
}

static void smtp_done(struct selector_key *key) {
	if (key->fd != -1) {
		if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, key->fd)) {
			abort();
		}
		close(key->fd);
	}
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

	state->request_parser.request = &state->request;
	request_parser_init(&state->request_parser);

	data_parser_init(&state->data_parser);

	buffer_init(&state->read_buffer, N(state->raw_buff_read), state->raw_buff_read);
	buffer_init(&state->write_buffer, N(state->raw_buff_write), state->raw_buff_write);

	const char* greeting = "220 localhost SMTP\r\n";
	const int len = strlen(greeting);

	memcpy(&state->raw_buff_write, greeting, len);
	buffer_write_adv(&state->write_buffer, len);

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

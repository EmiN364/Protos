#ifndef SMTPNIO_H
#define SMTPNIO_H

#include <stdint.h>
#include "buffer.h"
#include "stm.h"

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
 /** buffer utilizado para I/O */
 buffer               *rb, *wb;
 // struct hello_parser   parser;
 /** el método de autenticación seleccionado */
 uint8_t               method;
} ;

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct smtp {

 struct sockaddr_storage client_addr;

 socklen_t client_addr_len;

 int client_fd;
 int origin_fd;

 char *mail_from;
 char []recpt_to;

 /** maquinas de estados */
 struct state_machine          stm;

 /** estados para el client_fd */
 union {
  struct hello_st           hello;
  /*struct request_st         request;
  struct copy               copy;*/
 } client;
 /** estados para el origin_fd */
 /*union {
  struct connecting         conn;
  struct copy               copy;
 } orig;*/

};

/** obtiene el struct (smtp *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct smtp *)(key)->data)

/** Intenta aceptar la nueva conexión entrante*/
void
smtp_passive_accept(struct selector_key *key);

struct smtp* smtp_new(int client);

static void smtp_destroy(struct smtp *s);

#endif //SMTPNIO_H

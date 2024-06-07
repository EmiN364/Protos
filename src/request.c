/**
 * request.c -- parser del request de SMTP
 */
#include <string.h> // memset
#include <arpa/inet.h>

#include "request.h"

static void
remaining_set(struct request_parser* p, const int n) {
    p->i = 0;
    p->n = n;
}

static int
remaining_is_done(struct request_parser* p) {
    return p->i >= p->n;
}

//////////////////////////////////////////////////////////////////////////////

static enum request_state
verb(const uint8_t c, struct request_parser* p) {
    enum request_state next;
    if (c == ' ') {
        next = request_sep_arg1;
    } else {
        next = request_error;
    }
    /* switch (c) {
        case 0x05:
            next = request_sep_arg1;
            break;
        default:
            next = request_error;
            break;
    } */

    return next;
}

static enum request_state
cmd(const uint8_t c, struct request_parser* p) {
    p->request->cmd = c;

    return request_rsv;
}

static enum request_state
rsv(const uint8_t c, struct request_parser* p) {
    return request_atyp;
}


extern void
request_parser_init (struct request_parser* p) {
    p->state = request_verb;
    memset(p->request, 0, sizeof(*(p->request)));
}


extern enum request_state 
request_parser_feed (struct request_parser* p, const uint8_t c) {
    enum request_state next;

    switch(p->state) {
        case request_verb:
            next = verb(c, p);
            break;
        case request_sep_arg1:
            next = sep_arg(c, p);
            break;
        case request_arg1:
            next = arg1(c, p);
            break;
        case request_done:
        case request_error:
        /*case request_error_unsupported_version:
        case request_error_unsupported_atyp:*/
            next = p->state;
            break;
        default:
            next = request_error;
            break;
    }

    return p->state = next;
}

extern bool 
request_is_done(const enum request_state st, bool *errored) {
    if(st >= request_error && errored != 0) {
        *errored = true;
    }
    return st >= request_done;
}

extern enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;

    while(buffer_can_read(b)) {
       const uint8_t c = buffer_read(b);
       st = request_parser_feed(p, c);
       if(request_is_done(st, errored)) {
          break;
       }
    }
    return st;
}

extern void
request_close(struct request_parser *p) {
    // nada que hacer
}

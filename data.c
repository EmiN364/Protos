/**
 * request.c -- parser del request de SMTP
 */
#include <string.h> // memset
#include <arpa/inet.h>

#include "data.h"

static void
remaining_set(struct data_parser* p, const int n) {
    // p->i = 0;
    // p->n = n;
}

/* static int
remaining_is_done(struct data_parser* p) {
    return p->i >= p->n;
} */

//////////////////////////////////////////////////////////////////////////////

static enum data_state
verb(const uint8_t c, struct data_parser* p) {
    enum data_state next;
	switch (c) {
		case '\r':
			next = data_cr;
			break;
		default:
			next = data_verb;
	}
	if (next == data_verb) {
		if ( p->i < sizeof(p->request->verb) - 1) //TODO: Check this
			p->request->verb[p->i++] = (char) c;
	}
	else {
		p->request->verb[p->i] = 0;
		/*if (strcmp(p->request->verb, "data") == 0)
			next = data_data;*/
	}

    return next;
}


static enum data_state
write(const uint8_t c, struct data_parser* p) {
    p->request->arg1[0] = c;

    return data_done;
}


extern void
data_parser_init (struct data_parser* p) {
    p->state = data_verb;
    memset(p->request, 0, sizeof(*(p->request)));
}


extern enum data_state 
data_parser_feed (struct data_parser* p, const uint8_t c) {
    enum data_state next;

    switch(p->state) {
        case data_data:
			buffer_write(p->output_buffer, c);
        	next = data_data;
    		break;
        case data_cr:
            next = sep_arg1(c, p);
            break;
        case data_crlf:
            next = arg1(c, p);
            break;
        case data_crlfdot:
            switch (c) {
                case '\n':
                    next = data_done;
                    break;
                default:
                    next = data_verb;
                    break;
            }
            break;
    	case data_crlfdotcr:

        case data_done:
        default:
            next = data_done;
            break;
    }

    return p->state = next;
}

extern bool 
data_is_done(const enum data_state st, bool *errored) {
    return st >= data_done;
}

extern enum data_state
data_consume(buffer *b, struct data_parser *p, bool *errored) {
    enum data_state st = p->state;

    while(buffer_can_read(b)) {
       const uint8_t c = buffer_read(b);
       st = data_parser_feed(p, c);
       if(data_is_done(st, errored)) {
          break;
       }
    }
    return st;
}

extern void
data_close(struct data_parser *p) {
    // nada que hacer
}

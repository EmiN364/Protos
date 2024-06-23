/**
 * request.c -- parser del request de SMTP
 */
#include <string.h> // memset
#include <arpa/inet.h>

#include "data.h"

#define N(x) (sizeof(x) / sizeof((x)[0]))

extern void
data_parser_init (struct data_parser* p) {
    p->state = data_crlf;
	buffer_init(&p->output_buffer, N(p->raw_buffer), p->raw_buffer);
}


extern enum data_state 
data_parser_feed (struct data_parser* p, const uint8_t c) {
    enum data_state next;

    switch(p->state) {
        case data_data:
			if (c == '\r')
				next = data_cr;
			else {
				buffer_write(&p->output_buffer, c);
				next = data_data;
			}
    		break;
        case data_cr:
			if (c == '\n')
				next = data_crlf;
			else {
				buffer_write(&p->output_buffer, '\r');
				buffer_write(&p->output_buffer, c);
				next = data_data;
			}
            break;
        case data_crlf:
			if (c == '.')
				next = data_crlfdot;
			else {
				buffer_write(&p->output_buffer, '\r');
				buffer_write(&p->output_buffer, '\n');
				buffer_write(&p->output_buffer, c);
				next = data_data;
			}
            break;
        case data_crlfdot:
			if (c == '\r')
				next = data_crlfdotcr;
			else {
				buffer_write(&p->output_buffer, '\r');
				buffer_write(&p->output_buffer, '\n');
				buffer_write(&p->output_buffer, '.');
				buffer_write(&p->output_buffer, c);
				next = data_data;
			}
            break;
    	case data_crlfdotcr:
			if (c == '\n')
				next = data_done;
			else {
				buffer_write(&p->output_buffer, '\r');
				buffer_write(&p->output_buffer, '\n');
				buffer_write(&p->output_buffer, '.');
				buffer_write(&p->output_buffer, '\r');
				buffer_write(&p->output_buffer, c);
				next = data_data;
			}
			break;
        case data_done:
        default:
            next = data_done;
            break;
    }

    return p->state = next;
}

extern bool 
data_is_done(const enum data_state st) {
    return st >= data_done;
}

extern enum data_state
data_consume(buffer *b, struct data_parser *p) {
    enum data_state st = p->state;

    while(buffer_can_read(b)) {
       const uint8_t c = buffer_read(b);
       st = data_parser_feed(p, c);
       if(data_is_done(st)) {
          break;
       }
    }
    return st;
}

extern void
data_close(struct data_parser *p) {
    // nada que hacer
}

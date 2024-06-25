#ifndef SMTP_H
#define SMTP_H

#include "selector.h"

struct status {
  __uint32_t historic_connections, concurrent_connections, bytes_transfered, mails_sent;
  bool transformations;
  char * program;
};

void smtp_passive_accept(struct selector_key *key);

struct status * get_status();

#endif //SMTP_H
CC:= gcc
CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
SMTPD_CLI:= smtpd
SMTPD_OBJECTS:= args.o selector.o main.o

.PHONY: all clean

all: $(SMTPD_CLI)

$(SMTPD_CLI): $(SMTPD_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

args.o: args.h

selector.o: selector.h

clean:
	- rm $(SMTPD_CLI) *.o
CC:= gcc
CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
SMTPD_CLI:= smtpd
SMTPD_OBJECTS:= args.o selector.o main.o smtp.o stm.o buffer.o request.o

.PHONY: all clean test

all: $(SMTPD_CLI)

$(SMTPD_CLI): $(SMTPD_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: smtp.h

args.o: args.h

selector.o: selector.h

smtp.o: smtp.h stm.h buffer.h

stm.o: stm.h

buffer.o: buffer.h

request.o: request.h buffer.h

clean:
	- rm -f $(SMTPD_CLI) *.o request_test

request_test: request_test.o request.o buffer.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -pthread -lrt -lm -lsubunit

test: request_test
	./request_test
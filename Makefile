CC:= gcc
CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
SMTPD_CLI:= smtpd
MNG_CLI:= mng_client
SMTPD_OBJECTS:= args.o selector.o main.o smtp.o stm.o buffer.o request.o data.o udpServer.o utils.o

.PHONY: all clean test

all: $(SMTPD_CLI) $(MNG_CLI)

$(SMTPD_CLI): $(SMTPD_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(MNG_CLI): udpClient.o
	$(CC) $(CFLAGS) -o $@ $^

main.o: smtp.h udpServer.h mng.h utils.h

args.o: args.h

selector.o: selector.h

smtp.o: smtp.h stm.h buffer.h

stm.o: stm.h

buffer.o: buffer.h

request.o: request.h buffer.h

data.o: data.h buffer.h

utils.o: utils.h

udpClient.o: mng.h

udpServer.o: udpServer.h utils.h

clean:
	- rm -f $(SMTPD_CLI) *.o request_test stress_test $(MNG_CLI)

request_test: request_test.o request.o buffer.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -lrt -lm -lsubunit

buffer_test: buffer_test.o buffer.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -lrt -lm -lsubunit

stm_test: stm_test.o stm.o selector.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -lrt -lm -lsubunit

selector_test: selector_test.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -lrt -lm -lsubunit

stress_test: stress_test.o
	$(CC) $(CFLAGS) -o $@ $^

test: request_test buffer_test stm_test selector_test
	./request_test ; ./buffer_test ; ./stm_test ; ./selector_test

stress: stress_test
	./stress_test
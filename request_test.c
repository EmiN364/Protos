#include "request.h"
#include "tests.h"

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

START_TEST (test_data) {
    struct request request;
    struct request_parser parser = {
        .request = &request,
    };
    request_parser_init(&parser);
    uint8_t data[] = {
        'd', 'a', 't', 'a', '\r', '\n'
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state st = request_consume(&b, &parser, &errored);

    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, st);
}
END_TEST

START_TEST (test_mail_from) {
	struct request request;
	struct request_parser parser = {
		.request = &request,
	};
	request_parser_init(&parser);
	uint8_t data[] = {
		'm', 'a', 'i', 'l', ' ', 'f', 'r', 'o', 'm', ':', ' ', 'a', 'b', 'c', '\r', '\n'
	};
	buffer b; FIXBUF(b, data);
	bool errored = false;
	enum request_state st = request_consume(&b, &parser, &errored);

	ck_assert_uint_eq(false, errored);
	ck_assert_uint_eq(request_done, st);
}
END_TEST

START_TEST (test_verb_mult) {
	struct request request;
	struct request_parser parser = {
		.request = &request,
	};
	request_parser_init(&parser);
	uint8_t data[] = {
		'm', 'a', 'i', 'l',
	};
	buffer b; FIXBUF(b, data);
	bool errored = false;
	enum request_state st = request_consume(&b, &parser, &errored);

	ck_assert_uint_eq(false, errored);
	ck_assert_uint_eq(request_verb_mult, st);
}
END_TEST

START_TEST (test_rcpt_to) {
	struct request request;
	struct request_parser parser = {
		.request = &request,
	};
	request_parser_init(&parser);
	uint8_t data[] = {
		'r', 'c', 'p', 't', ' ', 't', 'o', ':', ' ', 'a', 'b', 'c', '\r', '\n'
	};
	buffer b; FIXBUF(b, data);
	bool errored = false;
	enum request_state st = request_consume(&b, &parser, &errored);

	ck_assert_uint_eq(false, errored);
	ck_assert_uint_eq(request_done, st);
}
END_TEST

START_TEST (test_invalid) {
	struct request request;
	struct request_parser parser = {
		.request = &request,
	};
	request_parser_init(&parser);
	uint8_t data[] = {
		'a', 's', 'd', 'a', '\r', '\n'
	};
	buffer b; FIXBUF(b, data);
	bool errored = false;
	enum request_state st = request_consume(&b, &parser, &errored);

	ck_assert_uint_eq(false, errored);
	ck_assert_uint_eq(request_done, st);
}
END_TEST

Suite *
request_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks");

    // Core test case
    tc = tcase_create("request");

	tcase_add_test(tc, test_data);
	tcase_add_test(tc, test_mail_from);
	tcase_add_test(tc, test_verb_mult);
	tcase_add_test(tc, test_rcpt_to);
	tcase_add_test(tc, test_invalid);

    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = request_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


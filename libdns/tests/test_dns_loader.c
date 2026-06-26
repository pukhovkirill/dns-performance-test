// test_dns_loader.c
#include "dns_loader.h"
#include "dns_iterator.h"
#include "dns_packet.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RUN_TEST(test_function) \
    do {                                           \
        test_function();                           \
        printf("[ PASSED ] %s\n", #test_function); \
    } while (0)

enum {
    TEST_PATH_SIZE = 256
};

static unsigned int test_file_counter;

static void create_test_file(
    char *path,
    const size_t path_size,
    const char *contents
)
{
    assert(path != NULL);
    assert(contents != NULL);

    const int written = snprintf(
        path,
        path_size,
        "/tmp/libdns_loader_%ld_%u.txt",
        (long)getpid(),
        test_file_counter++
    );

    assert(written > 0);
    assert((size_t)written < path_size);

    FILE *file = fopen(path, "wb");

    assert(file != NULL);

    const size_t contents_len = strlen(contents);

    assert(
        fwrite(contents, 1, contents_len, file) ==
        contents_len
    );

    assert(fclose(file) == 0);
}

static void remove_test_file(const char *path)
{
    assert(path != NULL);
    assert(remove(path) == 0);
}

static uint16_t read_u16_be(const uint8_t *src)
{
    assert(src != NULL);

    return (uint16_t)(
        ((uint16_t)src[0] << 8) |
        (uint16_t)src[1]
    );
}

static size_t find_qtype_offset(
    const uint8_t *packet,
    const size_t packet_len
)
{
    assert(packet != NULL);
    assert(packet_len > DNS_HDR_LEN);

    size_t offset = DNS_HDR_LEN;

    while (offset < packet_len) {
        const uint8_t label_len = packet[offset++];

        if (label_len == 0)
            return offset;

        assert(offset + label_len <= packet_len);
        offset += label_len;
    }

    assert(0 && "QNAME terminator was not found");
}

static void test_get_load_status(void)
{
    assert(get_load_status(LOAD_OK) == LOAD_OK);
    assert(get_load_status(1) == LOAD_OK);
    assert(get_load_status(100) == LOAD_OK);

    assert(
        get_load_status(LOAD_ERR_NULLPTR) ==
        LOAD_ERR_NULLPTR
    );

    assert(
        get_load_status(LOAD_ERR_NOFILE) ==
        LOAD_ERR_NOFILE
    );

    assert(
        get_load_status(LOAD_ERR_OPENFILE) ==
        LOAD_ERR_OPENFILE
    );

    assert(
        get_load_status(LOAD_ERR_READFILE) ==
        LOAD_ERR_READFILE
    );

    assert(
        get_load_status(LOAD_ERR_BADFORMAT) ==
        LOAD_ERR_BADFORMAT
    );

    assert(
        get_load_status(LOAD_ERR_BUFSIZE) ==
        LOAD_ERR_BUFSIZE
    );

    assert(
        get_load_status(LOAD_ERR_ALLOC) ==
        LOAD_ERR_ALLOC
    );

    assert(
        get_load_status(LOAD_ERR_UNKNOWN) ==
        LOAD_ERR_UNKNOWN
    );

    assert(get_load_status(-9) == LOAD_ERR_UNKNOWN);
    assert(get_load_status(-100) == LOAD_ERR_UNKNOWN);
}

static void test_load_null_destination(void)
{
    const ssize_t result = load_dns_queries_from_file(
        NULL,
        "queries.txt"
    );

    assert(result == LOAD_ERR_NULLPTR);
}

static void test_load_null_filename(void)
{
    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        NULL
    );

    assert(result == LOAD_ERR_NULLPTR);
    assert(array.data == NULL);
    assert(array.metadata == NULL);
}

static void test_load_missing_file(void)
{
    packet_array_t array = {0};

    char path[TEST_PATH_SIZE];

    const int written = snprintf(
        path,
        sizeof(path),
        "/tmp/libdns_missing_%ld_%u.txt",
        (long)getpid(),
        test_file_counter++
    );

    assert(written > 0);
    assert((size_t)written < sizeof(path));


    (void)remove(path);

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == LOAD_ERR_NOFILE);
    assert(array.data == NULL);
    assert(array.metadata == NULL);
}

static void test_load_single_query(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == 1);
    assert(array.data != NULL);
    assert(array.metadata != NULL);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == array.data);
    assert(entry.pkt_len == 29);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_loaded_query_header(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        1
    );

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt_len >= DNS_HDR_LEN);

    const uint16_t flags = read_u16_be(entry.pkt + 2);
    const uint16_t qdcount = read_u16_be(entry.pkt + 4);
    const uint16_t ancount = read_u16_be(entry.pkt + 6);
    const uint16_t nscount = read_u16_be(entry.pkt + 8);
    const uint16_t arcount = read_u16_be(entry.pkt + 10);

    assert((flags & DNS_FLAG_QR) == 0);
    assert((flags & DNS_MASK_OPCODE) == 0);

    assert(qdcount == 1);
    assert(ancount == 0);
    assert(nscount == 0);
    assert(arcount == 0);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_loaded_query_domain(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        1
    );

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    static const uint8_t expected_qname[] = {
        7,
        'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,
        'c', 'o', 'm',
        0
    };

    assert(
        memcmp(
            entry.pkt + DNS_HDR_LEN,
            expected_qname,
            sizeof(expected_qname)
        ) == 0
    );

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_loaded_query_type_and_class(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "AAAA example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        1
    );

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    const size_t qtype_offset = find_qtype_offset(
        entry.pkt,
        entry.pkt_len
    );

    assert(qtype_offset + 4 <= entry.pkt_len);

    assert(
        read_u16_be(entry.pkt + qtype_offset) ==
        DNS_QTYPE_AAAA
    );

    assert(
        read_u16_be(entry.pkt + qtype_offset + 2) ==
        DNS_QCLASS_IN
    );

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_load_query_with_spaces(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "   A     example.com    \n"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == 1);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    static const uint8_t expected_qname[] = {
        7,
        'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,
        'c', 'o', 'm',
        0
    };

    assert(
        memcmp(
            entry.pkt + DNS_HDR_LEN,
            expected_qname,
            sizeof(expected_qname)
        ) == 0
    );

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_load_query_with_windows_line_ending(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\r\n"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == 1);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt_len == 29);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_load_last_line_without_newline(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "MX example.com"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == 1);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    const size_t qtype_offset = find_qtype_offset(
        entry.pkt,
        entry.pkt_len
    );

    assert(
        read_u16_be(entry.pkt + qtype_offset) ==
        DNS_QTYPE_MX
    );

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_invalid_lines_are_ignored(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "invalid_line_without_domain\n"
        "A\n"
        "A     \n"
        "A bad domain.com\n"
        "A valid.example\n"
        "MX mail.example\n"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    /*
     * Only the following are valid:
     *  A valid.example
     *  MX mail.example
     */
    assert(result == 2);
    assert(array.data != NULL);
    assert(array.metadata != NULL);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    qiter_entry entry = qiter_next(iter);
    assert(entry.pkt != NULL);

    entry = qiter_next(iter);
    assert(entry.pkt != NULL);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_load_multiple_queries(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
        "AAAA localhost\n"
        "MX mail.example.com\n"
    );

    packet_array_t array = {0};

    const ssize_t result = load_dns_queries_from_file(
        &array,
        path
    );

    assert(result == 3);
    assert(array.data != NULL);
    assert(array.metadata != NULL);

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry first = qiter_next(iter);
    const qiter_entry second = qiter_next(iter);
    const qiter_entry third = qiter_next(iter);

    assert(first.pkt != NULL);
    assert(second.pkt != NULL);
    assert(third.pkt != NULL);

    assert(first.pkt_len == 29);
    assert(second.pkt_len == 27);
    assert(third.pkt_len == 34);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_multiple_queries_have_distinct_metadata(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
        "AAAA localhost\n"
        "MX mail.example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        3
    );

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry first = qiter_next(iter);
    const qiter_entry second = qiter_next(iter);
    const qiter_entry third = qiter_next(iter);

    /*
     * Each metadata element must point to
     * the beginning of the corresponding packet.
     */
    assert(first.pkt == array.data);
    assert(second.pkt == first.pkt + first.pkt_len);
    assert(third.pkt == second.pkt + second.pkt_len);

    assert(first.pkt != second.pkt);
    assert(second.pkt != third.pkt);
    assert(first.pkt != third.pkt);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_loaded_metadata_iterator_wraps_around(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A first.example\n"
        "A second.example\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        2
    );

    qiter_t *iter = qiter_create(array.metadata);

    assert(iter != NULL);

    const qiter_entry first = qiter_next(iter);
    const qiter_entry second = qiter_next(iter);
    const qiter_entry wrapped = qiter_next(iter);

    assert(first.pkt != second.pkt);

    assert(wrapped.pkt == first.pkt);
    assert(wrapped.pkt_len == first.pkt_len);

    qiter_destroy(iter);
    packet_array_destroy(&array);
    remove_test_file(path);
}

static void test_packet_array_destroy(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        1
    );

    assert(array.data != NULL);
    assert(array.metadata != NULL);

    packet_array_destroy(&array);

    assert(array.data == NULL);
    assert(array.metadata == NULL);

    remove_test_file(path);
}

static void test_packet_array_destroy_null(void)
{
    packet_array_destroy(NULL);
}

static void test_packet_array_destroy_empty_array(void)
{
    packet_array_t array = {0};

    packet_array_destroy(&array);

    assert(array.data == NULL);
    assert(array.metadata == NULL);
}

static void test_packet_array_destroy_twice(void)
{
    char path[TEST_PATH_SIZE];

    create_test_file(
        path,
        sizeof(path),
        "A example.com\n"
    );

    packet_array_t array = {0};

    assert(
        load_dns_queries_from_file(&array, path) ==
        1
    );

    packet_array_destroy(&array);
    packet_array_destroy(&array);

    assert(array.data == NULL);
    assert(array.metadata == NULL);

    remove_test_file(path);
}

void test_dns_loader_all(void)
{
    printf("========================================\n");
    printf("Running dns_loader.h tests\n");
    printf("========================================\n");

    RUN_TEST(test_get_load_status);

    RUN_TEST(test_load_null_destination);
    RUN_TEST(test_load_null_filename);
    RUN_TEST(test_load_missing_file);

    RUN_TEST(test_load_single_query);
    RUN_TEST(test_loaded_query_header);
    RUN_TEST(test_loaded_query_domain);
    RUN_TEST(test_loaded_query_type_and_class);

    RUN_TEST(test_load_query_with_spaces);
    RUN_TEST(test_load_query_with_windows_line_ending);
    RUN_TEST(test_load_last_line_without_newline);
    RUN_TEST(test_invalid_lines_are_ignored);

    RUN_TEST(test_load_multiple_queries);
    RUN_TEST(test_multiple_queries_have_distinct_metadata);
    RUN_TEST(test_loaded_metadata_iterator_wraps_around);

    RUN_TEST(test_packet_array_destroy);
    RUN_TEST(test_packet_array_destroy_null);
    RUN_TEST(test_packet_array_destroy_empty_array);
    RUN_TEST(test_packet_array_destroy_twice);

    printf("========================================\n");
    printf("All dns_loader.h tests passed\n");
    printf("========================================\n");
}
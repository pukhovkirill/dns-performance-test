// test_dns_utils.c
#include "../src/dns_utils.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>


#define RUN_TEST(test_function) \
    do {                                            \
        test_function();                            \
        printf("[ PASSED ] %s\n", #test_function);  \
    } while (0)


static void test_dns_write_u16_zero(void)
{
    uint8_t buffer[2] = {
        0xFF, 0xFF
    };

    const size_t written = dns_write_u16(
        buffer,
        0
    );

    assert(written == 2);
    assert(buffer[0] == 0x00);
    assert(buffer[1] == 0x00);
}


static void test_dns_write_u16_big_endian(void)
{
    uint8_t buffer[2] = {
        0x00, 0x00
    };

    const size_t written = dns_write_u16(
        buffer,
        0x1234
    );

    assert(written == 2);
    assert(buffer[0] == 0x12);
    assert(buffer[1] == 0x34);
}


static void test_dns_write_u16_max_value(void)
{
    uint8_t buffer[2] = {
        0x00, 0x00
    };

    const size_t written = dns_write_u16(
        buffer,
        UINT16_MAX
    );

    assert(written == 2);
    assert(buffer[0] == 0xFF);
    assert(buffer[1] == 0xFF);
}


static void test_dns_write_u16_does_not_modify_surrounding_bytes(void)
{
    uint8_t buffer[4] = {
        0xAA, 0x00, 0x00, 0xBB
    };

    const size_t written = dns_write_u16(
        &buffer[1],
        0x1234
    );

    assert(written == 2);

    assert(buffer[0] == 0xAA);
    assert(buffer[1] == 0x12);
    assert(buffer[2] == 0x34);
    assert(buffer[3] == 0xBB);
}


static void test_dns_read_u16_zero(void)
{
    static const uint8_t buffer[] = {
        0x00, 0x00
    };

    const uint16_t value = dns_read_u16(buffer);

    assert(value == 0);
}


static void test_dns_read_u16_big_endian(void)
{
    static const uint8_t buffer[] = {
        0x12, 0x34
    };

    const uint16_t value = dns_read_u16(buffer);

    assert(value == 0x1234);
}


static void test_dns_read_u16_max_value(void)
{
    static const uint8_t buffer[] = {
        0xFF, 0xFF
    };

    const uint16_t value = dns_read_u16(buffer);

    assert(value == UINT16_MAX);
}


static void test_dns_read_u16_from_unaligned_address(void)
{
    static const uint8_t buffer[] = {
        0xAA, 0xAB, 0xCD, 0xBB
    };

    const uint16_t value = dns_read_u16(&buffer[1]);

    assert(value == 0xABCD);
}


static void test_dns_write_and_read_u16_round_trip(void)
{
    static const uint16_t values[] = {
        0x0000,
        0x0001,
        0x00FF,
        0x0100,
        0x1234,
        0x8000,
        0xFFFF
    };

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint8_t buffer[2];

        const size_t written = dns_write_u16(
            buffer,
            values[i]
        );

        assert(written == 2);
        assert(dns_read_u16(buffer) == values[i]);
    }
}


static void test_str_to_dns_qtype_null(void)
{
    const dns_qtype_t qtype = str_to_dns_qtype(
        NULL,
        1
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_a(void)
{
    static const char value[] = "A";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        1
    );

    assert(qtype == DNS_QTYPE_A);
}


static void test_str_to_dns_qtype_mx(void)
{
    static const char value[] = "MX";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        2
    );

    assert(qtype == DNS_QTYPE_MX);
}


static void test_str_to_dns_qtype_aaaa(void)
{
    static const char value[] = "AAAA";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        4
    );

    assert(qtype == DNS_QTYPE_AAAA);
}


static void test_str_to_dns_qtype_unknown(void)
{
    static const char value[] = "UNKNOWN";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        7
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_is_case_sensitive(void)
{
    static const char value[] = "a";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        1
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_shorter_length(void)
{
    static const char value[] = "AAAA";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        3
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_longer_length(void)
{
    static const char value[] = "A";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        2
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_zero_length(void)
{
    static const char value[] = "A";

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        0
    );

    assert(qtype == DNS_QTYPE_NOT_IMPLEMENTED);
}


static void test_str_to_dns_qtype_does_not_require_null_terminator(void)
{
    static const char value[] = {
        'M', 'X', 'X'
    };

    const dns_qtype_t qtype = str_to_dns_qtype(
        value,
        2
    );

    assert(qtype == DNS_QTYPE_MX);
}


static void test_dns_qname_encoded_size_null(void)
{
    const size_t size = dns_qname_encoded_size(NULL);

    assert(size == 0);
}


static void test_dns_qname_encoded_size_empty(void)
{
    const size_t size = dns_qname_encoded_size("");

    assert(size == 0);
}


static void test_dns_qname_encoded_size_without_trailing_dot(void)
{
    const size_t size = dns_qname_encoded_size(
        "google.com"
    );

    /*
     * [6]google[3]com[0]
     */
    assert(size == 12);
}


static void test_dns_qname_encoded_size_with_trailing_dot(void)
{
    const size_t size = dns_qname_encoded_size(
        "google.com."
    );

    /*
     * [6]google[3]com[0]
     */
    assert(size == 12);
}


static void test_dns_qname_encoded_size_single_label(void)
{
    const size_t size = dns_qname_encoded_size(
        "localhost"
    );

    /*
     * [9]localhost[0]
     */
    assert(size == 11);
}


static void test_dns_qname_encoded_size_single_label_with_trailing_dot(void)
{
    const size_t size = dns_qname_encoded_size(
        "localhost."
    );

    /*
     * [9]localhost[0]
     */
    assert(size == 11);
}


static void test_dns_qname_encoded_size_multiple_labels(void)
{
    const size_t size = dns_qname_encoded_size(
        "www.example.com"
    );

    /*
     * [3]www[7]example[3]com[0]
     */
    assert(size == 17);
}


void test_dns_utils_all(void)
{
    printf("========================================\n");
    printf("Running dns_utils.h tests\n");
    printf("========================================\n");

    RUN_TEST(test_dns_write_u16_zero);
    RUN_TEST(test_dns_write_u16_big_endian);
    RUN_TEST(test_dns_write_u16_max_value);
    RUN_TEST(test_dns_write_u16_does_not_modify_surrounding_bytes);

    RUN_TEST(test_dns_read_u16_zero);
    RUN_TEST(test_dns_read_u16_big_endian);
    RUN_TEST(test_dns_read_u16_max_value);
    RUN_TEST(test_dns_read_u16_from_unaligned_address);
    RUN_TEST(test_dns_write_and_read_u16_round_trip);

    RUN_TEST(test_str_to_dns_qtype_null);
    RUN_TEST(test_str_to_dns_qtype_a);
    RUN_TEST(test_str_to_dns_qtype_mx);
    RUN_TEST(test_str_to_dns_qtype_aaaa);
    RUN_TEST(test_str_to_dns_qtype_unknown);
    RUN_TEST(test_str_to_dns_qtype_is_case_sensitive);
    RUN_TEST(test_str_to_dns_qtype_shorter_length);
    RUN_TEST(test_str_to_dns_qtype_longer_length);
    RUN_TEST(test_str_to_dns_qtype_zero_length);
    RUN_TEST(test_str_to_dns_qtype_does_not_require_null_terminator);

    RUN_TEST(test_dns_qname_encoded_size_null);
    RUN_TEST(test_dns_qname_encoded_size_empty);
    RUN_TEST(test_dns_qname_encoded_size_without_trailing_dot);
    RUN_TEST(test_dns_qname_encoded_size_with_trailing_dot);
    RUN_TEST(test_dns_qname_encoded_size_single_label);
    RUN_TEST(test_dns_qname_encoded_size_single_label_with_trailing_dot);
    RUN_TEST(test_dns_qname_encoded_size_multiple_labels);

    printf("========================================\n");
    printf("All dns_utils.h tests passed\n");
    printf("========================================\n");
}

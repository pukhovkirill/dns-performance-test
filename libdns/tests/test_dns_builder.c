// test_dns_builder.c
#include "dns_builder.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RUN_TEST(test_function) \
    do {                                           \
        test_function();                           \
        printf("[ PASSED ] %s\n", #test_function); \
    } while (0)

enum {
    TEST_BUFFER_SIZE = 512
};

static uint16_t read_u16_be(const uint8_t *src)
{
    assert(src != NULL);

    return (uint16_t)(
        ((uint16_t)src[0] << 8) |
        (uint16_t)src[1]
    );
}

static void test_get_build_status(void)
{
    assert(get_build_status(BUILD_OK) == BUILD_OK);
    assert(get_build_status(1) == BUILD_OK);
    assert(get_build_status(100) == BUILD_OK);

    assert(
        get_build_status(BUILD_ERR_NULLPTR) ==
        BUILD_ERR_NULLPTR
    );

    assert(
        get_build_status(BUILD_ERR_BUFSIZE) ==
        BUILD_ERR_BUFSIZE
    );

    assert(
        get_build_status(BUILD_ERR_UNKNOWN) ==
        BUILD_ERR_UNKNOWN
    );

    assert(get_build_status(-4) == BUILD_ERR_UNKNOWN);
    assert(get_build_status(-100) == BUILD_ERR_UNKNOWN);
}

static void test_dns_build_query_null_buffer(void)
{
    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(NULL, 0, query);

    assert(result == BUILD_ERR_NULLPTR);
}

static void test_dns_build_query_buffer_too_small_for_header(void)
{
    uint8_t buffer[DNS_HDR_LEN - 1] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == BUILD_ERR_BUFSIZE);
}

static void test_dns_build_query_buffer_too_small_for_question(void)
{
    /*
     * The buffer is sufficient for the header but insufficient
     * for the DNS question.
     */
    uint8_t buffer[DNS_HDR_LEN] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == BUILD_ERR_BUFSIZE);
}

static void test_dns_build_query_returns_packet_size(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    /*
     * Header: 12 bytes.
     *
     * example.com:
     *   1 + 7 — mark "example";
     *   1 + 3 — mark "com";
     *   1     — trailing zero;
     *   2     — QTYPE;
     *   2     — QCLASS.
     *
     * Total: 12 + 13 + 4 = 29.
     */
    assert(result == 29);
}

static void test_dns_build_query_header(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result > 0);

    const uint16_t flags = read_u16_be(buffer + 2);
    const uint16_t qdcount = read_u16_be(buffer + 4);
    const uint16_t ancount = read_u16_be(buffer + 6);
    const uint16_t nscount = read_u16_be(buffer + 8);
    const uint16_t arcount = read_u16_be(buffer + 10);

    /*
     * default DNS request:
     * QR = 0, OPCODE = QUERY, the remaining flags are equal to zero.
     */
    assert(flags == 0);

    assert(qdcount == 1);
    assert(ancount == 0);
    assert(nscount == 0);
    assert(arcount == 0);
}

static void test_dns_build_query_encodes_domain(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == 29);

    static const uint8_t expected_qname[] = {
        7,
        'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,
        'c', 'o', 'm',
        0
    };

    assert(
        memcmp(
            buffer + DNS_HDR_LEN,
            expected_qname,
            sizeof(expected_qname)
        ) == 0
    );
}

static void test_dns_build_query_domain_with_trailing_dot(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com.",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == 29);

    static const uint8_t expected_qname[] = {
        7,
        'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,
        'c', 'o', 'm',
        0
    };

    assert(
        memcmp(
            buffer + DNS_HDR_LEN,
            expected_qname,
            sizeof(expected_qname)
        ) == 0
    );
}

static void test_dns_build_query_single_label_domain(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "localhost",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    /*
     * Header: 12.
     * QNAME: 1 + 9 + 1 = 11.
     * QTYPE and QCLASS: 4.
     *
     * Total: 27.
     */
    assert(result == 27);

    static const uint8_t expected_qname[] = {
        9,
        'l', 'o', 'c', 'a', 'l',
        'h', 'o', 's', 't',
        0
    };

    assert(
        memcmp(
            buffer + DNS_HDR_LEN,
            expected_qname,
            sizeof(expected_qname)
        ) == 0
    );
}

static void test_dns_build_query_question_type_and_class(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_AAAA,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == 29);

    /*
     * QNAME occupies 13 bytes:
     * 7example3com0.
     */
    const size_t qtype_offset = DNS_HDR_LEN + 13;
    const size_t qclass_offset = qtype_offset + sizeof(uint16_t);

    assert(
        read_u16_be(buffer + qtype_offset) ==
        DNS_QTYPE_AAAA
    );

    assert(
        read_u16_be(buffer + qclass_offset) ==
        DNS_QCLASS_IN
    );
}

static void test_dns_build_query_exact_buffer_size(void)
{
    uint8_t buffer[29] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t result = dns_build_query(
        buffer,
        sizeof(buffer),
        query
    );

    assert(result == (ssize_t)sizeof(buffer));
}

static void test_dns_build_query_ids_are_sequential(void)
{
    uint8_t first_packet[TEST_BUFFER_SIZE] = {0};
    uint8_t second_packet[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    assert(
        dns_build_query(
            first_packet,
            sizeof(first_packet),
            query
        ) > 0
    );

    assert(
        dns_build_query(
            second_packet,
            sizeof(second_packet),
            query
        ) > 0
    );

    const uint16_t first_id = read_u16_be(first_packet);
    const uint16_t second_id = read_u16_be(second_packet);

    assert(second_id == (uint16_t)(first_id + 1));
}

static void test_dns_pkt_to_response_null_packet(void)
{
    const ssize_t result = dns_pkt_to_response(NULL, 0);

    assert(result == BUILD_ERR_NULLPTR);
}

static void test_dns_pkt_to_response_buffer_too_small(void)
{
    uint8_t buffer[3] = {0};

    assert(
        dns_pkt_to_response(buffer, 0) ==
        BUILD_ERR_BUFSIZE
    );

    assert(
        dns_pkt_to_response(buffer, 1) ==
        BUILD_ERR_BUFSIZE
    );

    assert(
        dns_pkt_to_response(buffer, 2) ==
        BUILD_ERR_BUFSIZE
    );

    assert(
        dns_pkt_to_response(buffer, 3) ==
        BUILD_ERR_BUFSIZE
    );
}

static void test_dns_pkt_to_response_sets_qr_flag(void)
{
    uint8_t packet[DNS_HDR_LEN] = {0};

    assert(read_u16_be(packet + 2) == 0);

    const ssize_t result = dns_pkt_to_response(
        packet,
        sizeof(packet)
    );

    assert(result == BUILD_OK);

    const uint16_t flags = read_u16_be(packet + 2);

    assert((flags & DNS_FLAG_QR) != 0);
}

static void test_dns_pkt_to_response_preserves_other_flags(void)
{
    uint8_t packet[DNS_HDR_LEN] = {0};

    const uint16_t original_flags =
        DNS_FLAG_AA |
        DNS_FLAG_TC |
        DNS_FLAG_RD |
        DNS_FLAG_RA |
        DNS_RCODE_REFUSED;

    packet[2] = (uint8_t)(original_flags >> 8);
    packet[3] = (uint8_t)(original_flags & 0xFF);

    const ssize_t result = dns_pkt_to_response(
        packet,
        sizeof(packet)
    );

    assert(result == BUILD_OK);

    const uint16_t actual_flags = read_u16_be(packet + 2);

    assert((actual_flags & DNS_FLAG_QR) != 0);

    assert(
        (actual_flags & (uint16_t)~DNS_FLAG_QR) ==
        original_flags
    );
}

static void test_dns_pkt_to_response_does_not_modify_other_bytes(void)
{
    uint8_t packet[DNS_HDR_LEN] = {
        0x12, 0x34, /* ID */
        0x01, 0x00, /* flags: RD */
        0x00, 0x01, /* QDCOUNT */
        0x00, 0x02, /* ANCOUNT */
        0x00, 0x03, /* NSCOUNT */
        0x00, 0x04  /* ARCOUNT */
    };

    uint8_t expected[DNS_HDR_LEN];
    memcpy(expected, packet, sizeof(expected));

    /*
     * Only the flags bytes should change.
     */
    expected[2] |= 0x80;

    const ssize_t result = dns_pkt_to_response(
        packet,
        sizeof(packet)
    );

    assert(result == BUILD_OK);
    assert(memcmp(packet, expected, sizeof(packet)) == 0);
}

static void test_dns_build_query_then_convert_to_response(void)
{
    uint8_t packet[TEST_BUFFER_SIZE] = {0};

    dns_query_t query = {
        .domain = "example.com",
        .qtype = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    const ssize_t packet_size = dns_build_query(
        packet,
        sizeof(packet),
        query
    );

    assert(packet_size > 0);

    const uint16_t id_before = read_u16_be(packet);
    const uint16_t flags_before = read_u16_be(packet + 2);
    const uint16_t qdcount_before = read_u16_be(packet + 4);

    assert((flags_before & DNS_FLAG_QR) == 0);

    const ssize_t result = dns_pkt_to_response(
        packet,
        (size_t)packet_size
    );

    assert(result == BUILD_OK);

    const uint16_t id_after = read_u16_be(packet);
    const uint16_t flags_after = read_u16_be(packet + 2);
    const uint16_t qdcount_after = read_u16_be(packet + 4);

    assert(id_after == id_before);
    assert(qdcount_after == qdcount_before);
    assert((flags_after & DNS_FLAG_QR) != 0);
}

void test_dns_builder_all(void)
{
    printf("========================================\n");
    printf("Running dns_builder.h tests\n");
    printf("========================================\n");

    RUN_TEST(test_get_build_status);

    RUN_TEST(test_dns_build_query_null_buffer);
    RUN_TEST(test_dns_build_query_buffer_too_small_for_header);
    RUN_TEST(test_dns_build_query_buffer_too_small_for_question);

    RUN_TEST(test_dns_build_query_returns_packet_size);
    RUN_TEST(test_dns_build_query_header);
    RUN_TEST(test_dns_build_query_encodes_domain);
    RUN_TEST(test_dns_build_query_domain_with_trailing_dot);
    RUN_TEST(test_dns_build_query_single_label_domain);
    RUN_TEST(test_dns_build_query_question_type_and_class);
    RUN_TEST(test_dns_build_query_exact_buffer_size);
    RUN_TEST(test_dns_build_query_ids_are_sequential);

    RUN_TEST(test_dns_pkt_to_response_null_packet);
    RUN_TEST(test_dns_pkt_to_response_buffer_too_small);
    RUN_TEST(test_dns_pkt_to_response_sets_qr_flag);
    RUN_TEST(test_dns_pkt_to_response_preserves_other_flags);
    RUN_TEST(test_dns_pkt_to_response_does_not_modify_other_bytes);

    RUN_TEST(test_dns_build_query_then_convert_to_response);

    printf("========================================\n");
    printf("All dns_builder.h tests passed\n");
    printf("========================================\n");
}
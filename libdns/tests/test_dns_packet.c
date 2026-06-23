// test_dns_packet.c
#include "dns_packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define RUN_TEST(test_function) \
    do {                                           \
        test_function();                           \
        printf("[ PASSED ] %s\n", #test_function); \
    } while (0)

static void test_dns_header_size(void)
{
    assert(DNS_HDR_LEN == 12);
    assert(sizeof(dns_hdr_t) == DNS_HDR_LEN);
}

static void test_packet_type(void)
{
    dns_hdr_t hdr = {0};

    assert(packet_type(&hdr) == DNS_PKT_QUERY);

    dns_set_packet_type(&hdr, DNS_PKT_RESPONSE);
    assert(packet_type(&hdr) == DNS_PKT_RESPONSE);
    assert((hdr.flags & DNS_FLAG_QR) != 0);

    dns_set_packet_type(&hdr, DNS_PKT_QUERY);
    assert(packet_type(&hdr) == DNS_PKT_QUERY);
    assert((hdr.flags & DNS_FLAG_QR) == 0);
}

static void test_packet_type_preserves_other_flags(void)
{
    dns_hdr_t hdr = {
        .flags = DNS_FLAG_AA |
                 DNS_FLAG_TC |
                 DNS_FLAG_RD |
                 DNS_FLAG_RA |
                 DNS_RCODE_REFUSED
    };

    const uint16_t original_flags = hdr.flags;

    dns_set_packet_type(&hdr, DNS_PKT_RESPONSE);

    assert((hdr.flags & DNS_FLAG_QR) != 0);
    assert((hdr.flags & ~DNS_FLAG_QR) == original_flags);

    dns_set_packet_type(&hdr, DNS_PKT_QUERY);

    assert((hdr.flags & DNS_FLAG_QR) == 0);
    assert(hdr.flags == original_flags);
}

static void test_query_type(void)
{
    static const dns_op_t operations[] = {
        DNS_OP_QUERY,
        DNS_OP_IQUERY,
        DNS_OP_STATUS
    };

    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        dns_hdr_t hdr = {0};

        dns_set_query_type(&hdr, operations[i]);

        assert(query_type(&hdr) == operations[i]);
        assert(
            (hdr.flags & DNS_MASK_OPCODE) ==
            (((uint16_t)operations[i] << 11) & DNS_MASK_OPCODE)
        );
    }
}

static void test_query_type_replaces_previous_value(void)
{
    dns_hdr_t hdr = {0};

    dns_set_query_type(&hdr, DNS_OP_STATUS);
    assert(query_type(&hdr) == DNS_OP_STATUS);

    dns_set_query_type(&hdr, DNS_OP_IQUERY);
    assert(query_type(&hdr) == DNS_OP_IQUERY);

    dns_set_query_type(&hdr, DNS_OP_QUERY);
    assert(query_type(&hdr) == DNS_OP_QUERY);
    assert((hdr.flags & DNS_MASK_OPCODE) == 0);
}

static void test_query_type_preserves_other_flags(void)
{
    dns_hdr_t hdr = {
        .flags = DNS_FLAG_QR |
                 DNS_FLAG_AA |
                 DNS_FLAG_TC |
                 DNS_FLAG_RD |
                 DNS_FLAG_RA |
                 DNS_RCODE_NAME_ERROR
    };

    const uint16_t flags_outside_opcode =
        (uint16_t)(hdr.flags & ~DNS_MASK_OPCODE);

    dns_set_query_type(&hdr, DNS_OP_STATUS);

    assert(query_type(&hdr) == DNS_OP_STATUS);
    assert(
        (hdr.flags & ~DNS_MASK_OPCODE) ==
        flags_outside_opcode
    );
}

static void test_authoritative_answer(void)
{
    dns_hdr_t hdr = {0};

    assert(!is_authoritative_answer(&hdr));

    dns_set_authoritative_answer(&hdr);

    assert(is_authoritative_answer(&hdr));
    assert((hdr.flags & DNS_FLAG_AA) != 0);
}

static void test_truncated(void)
{
    dns_hdr_t hdr = {0};

    assert(!is_truncated(&hdr));

    dns_set_truncated(&hdr);

    assert(is_truncated(&hdr));
    assert((hdr.flags & DNS_FLAG_TC) != 0);
}

static void test_recursion_desired(void)
{
    dns_hdr_t hdr = {0};

    assert(!is_recursion_desired(&hdr));

    dns_set_recursion_desired(&hdr);

    assert(is_recursion_desired(&hdr));
    assert((hdr.flags & DNS_FLAG_RD) != 0);
}

static void test_recursion_available(void)
{
    dns_hdr_t hdr = {0};

    assert(!is_recursion_available(&hdr));

    dns_set_recursion_available(&hdr);

    assert(is_recursion_available(&hdr));
    assert((hdr.flags & DNS_FLAG_RA) != 0);
}

static void test_boolean_setters_preserve_other_flags(void)
{
    dns_hdr_t hdr = {
        .flags = DNS_FLAG_QR | DNS_RCODE_SERVER_FAILURE
    };

    dns_set_authoritative_answer(&hdr);
    dns_set_truncated(&hdr);
    dns_set_recursion_desired(&hdr);
    dns_set_recursion_available(&hdr);

    assert(packet_type(&hdr) == DNS_PKT_RESPONSE);
    assert(response_code(&hdr) == DNS_RCODE_SERVER_FAILURE);
    assert(is_authoritative_answer(&hdr));
    assert(is_truncated(&hdr));
    assert(is_recursion_desired(&hdr));
    assert(is_recursion_available(&hdr));
}

static void test_response_code(void)
{
    static const dns_rcode_t codes[] = {
        DNS_RCODE_NO_ERROR,
        DNS_RCODE_FORMAT_ERROR,
        DNS_RCODE_SERVER_FAILURE,
        DNS_RCODE_NAME_ERROR,
        DNS_RCODE_NOT_IMPLEMENTED,
        DNS_RCODE_REFUSED
    };

    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        dns_hdr_t hdr = {0};

        dns_set_response_code(&hdr, codes[i]);

        assert(response_code(&hdr) == codes[i]);
        assert(
            (hdr.flags & DNS_MASK_RCODE) ==
            ((uint16_t)codes[i] & DNS_MASK_RCODE)
        );
    }
}

static void test_response_code_replaces_previous_value(void)
{
    dns_hdr_t hdr = {0};

    dns_set_response_code(&hdr, DNS_RCODE_REFUSED);
    assert(response_code(&hdr) == DNS_RCODE_REFUSED);

    dns_set_response_code(&hdr, DNS_RCODE_NAME_ERROR);
    assert(response_code(&hdr) == DNS_RCODE_NAME_ERROR);

    dns_set_response_code(&hdr, DNS_RCODE_NO_ERROR);
    assert(response_code(&hdr) == DNS_RCODE_NO_ERROR);
    assert((hdr.flags & DNS_MASK_RCODE) == 0);
}

static void test_response_code_preserves_other_flags(void)
{
    dns_hdr_t hdr = {
        .flags = DNS_FLAG_QR |
                 DNS_FLAG_AA |
                 DNS_FLAG_TC |
                 DNS_FLAG_RD |
                 DNS_FLAG_RA
    };

    dns_set_query_type(&hdr, DNS_OP_STATUS);

    const uint16_t flags_outside_rcode =
        (uint16_t)(hdr.flags & ~DNS_MASK_RCODE);

    dns_set_response_code(&hdr, DNS_RCODE_REFUSED);

    assert(response_code(&hdr) == DNS_RCODE_REFUSED);
    assert(
        (hdr.flags & ~DNS_MASK_RCODE) ==
        flags_outside_rcode
    );
}

static void test_all_header_fields_together(void)
{
    dns_hdr_t hdr = {
        .id      = 0x1234,
        .flags   = 0,
        .qdcount = 1,
        .ancount = 2,
        .nscount = 3,
        .arcount = 4
    };

    dns_set_packet_type(&hdr, DNS_PKT_RESPONSE);
    dns_set_query_type(&hdr, DNS_OP_STATUS);
    dns_set_authoritative_answer(&hdr);
    dns_set_truncated(&hdr);
    dns_set_recursion_desired(&hdr);
    dns_set_recursion_available(&hdr);
    dns_set_response_code(&hdr, DNS_RCODE_NAME_ERROR);

    assert(hdr.id == 0x1234);
    assert(hdr.qdcount == 1);
    assert(hdr.ancount == 2);
    assert(hdr.nscount == 3);
    assert(hdr.arcount == 4);

    assert(packet_type(&hdr) == DNS_PKT_RESPONSE);
    assert(query_type(&hdr) == DNS_OP_STATUS);
    assert(is_authoritative_answer(&hdr));
    assert(is_truncated(&hdr));
    assert(is_recursion_desired(&hdr));
    assert(is_recursion_available(&hdr));
    assert(response_code(&hdr) == DNS_RCODE_NAME_ERROR);
}

static void test_question_type(void)
{
    dns_question_t question = {
        .qname  = "example.com",
        .qtype  = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    assert(question_type(&question) == DNS_QTYPE_A);

    question.qtype = DNS_QTYPE_MX;
    assert(question_type(&question) == DNS_QTYPE_MX);

    question.qtype = DNS_QTYPE_AAAA;
    assert(question_type(&question) == DNS_QTYPE_AAAA);

    question.qtype = DNS_QTYPE_NOT_IMPLEMENTED;
    assert(question_type(&question) == DNS_QTYPE_NOT_IMPLEMENTED);
}

static void test_question_class(void)
{
    dns_question_t question = {
        .qname  = "example.com",
        .qtype  = DNS_QTYPE_A,
        .qclass = DNS_QCLASS_IN
    };

    assert(question_class(&question) == DNS_QCLASS_IN);

    question.qclass = DNS_QCLASS_NOT_IMPLEMENTED;
    assert(
        question_class(&question) ==
        DNS_QCLASS_NOT_IMPLEMENTED
    );
}

static void test_question_name_is_not_modified(void)
{
    const char *name = "www.example.com";

    dns_question_t question = {
        .qname  = name,
        .qtype  = DNS_QTYPE_AAAA,
        .qclass = DNS_QCLASS_IN
    };

    (void)question_type(&question);
    (void)question_class(&question);

    assert(question.qname == name);
    assert(strcmp(question.qname, "www.example.com") == 0);
}

void test_dns_packet_all(void)
{
    printf("========================================\n");
    printf("Running dns_packet.h tests\n");
    printf("========================================\n");

    RUN_TEST(test_dns_header_size);

    RUN_TEST(test_packet_type);
    RUN_TEST(test_packet_type_preserves_other_flags);

    RUN_TEST(test_query_type);
    RUN_TEST(test_query_type_replaces_previous_value);
    RUN_TEST(test_query_type_preserves_other_flags);

    RUN_TEST(test_authoritative_answer);
    RUN_TEST(test_truncated);
    RUN_TEST(test_recursion_desired);
    RUN_TEST(test_recursion_available);
    RUN_TEST(test_boolean_setters_preserve_other_flags);

    RUN_TEST(test_response_code);
    RUN_TEST(test_response_code_replaces_previous_value);
    RUN_TEST(test_response_code_preserves_other_flags);

    RUN_TEST(test_all_header_fields_together);

    RUN_TEST(test_question_type);
    RUN_TEST(test_question_class);
    RUN_TEST(test_question_name_is_not_modified);

    printf("========================================\n");
    printf("All dns_packet.h tests passed\n");
    printf("========================================\n");
}
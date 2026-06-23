// dns_packet.h
#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

enum { DNS_HDR_LEN = 12 };

enum {
    DNS_FLAG_QR = 0x8000,
    DNS_FLAG_AA = 0x0400,
    DNS_FLAG_TC = 0x0200,
    DNS_FLAG_RD = 0x0100,
    DNS_FLAG_RA = 0x0080,

    DNS_MASK_OPCODE = 0x7800,   // bits 14..11
    DNS_MASK_RCODE  = 0x000F,   // bits 3..0
};

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

typedef enum {
    DNS_PKT_QUERY    = 0,
    DNS_PKT_RESPONSE = 1
} dns_pkt_type_t;

typedef enum {
    DNS_OP_QUERY  = 0,
    DNS_OP_IQUERY = 1,
    DNS_OP_STATUS = 2
} dns_op_t;

typedef enum {
    DNS_RCODE_NO_ERROR        = 0,
    DNS_RCODE_FORMAT_ERROR    = 1,
    DNS_RCODE_SERVER_FAILURE  = 2,
    DNS_RCODE_NAME_ERROR      = 3,
    DNS_RCODE_NOT_IMPLEMENTED = 4,
    DNS_RCODE_REFUSED         = 5
} dns_rcode_t;

static void dns_set_packet_type(dns_hdr_t *hdr, dns_pkt_type_t type)
{
    assert(hdr != NULL);
    if (type == DNS_PKT_RESPONSE)
        hdr->flags |= DNS_FLAG_QR;
    else
        hdr->flags &= ~DNS_FLAG_QR;
}

static void dns_set_query_type(dns_hdr_t *hdr, dns_op_t op)
{
    assert(hdr != NULL);
    hdr->flags &= ~DNS_MASK_OPCODE;
    hdr->flags |= ((uint16_t)op << 11) & DNS_MASK_OPCODE;
}

static void dns_set_authoritative_answer(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_AA;
}

static void dns_set_truncated(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_TC;
}

static void dns_set_recursion_desired(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_RD;
}

static void dns_set_recursion_available(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_RA;
}

static void dns_set_response_code(dns_hdr_t *hdr, dns_rcode_t code)
{
    assert(hdr != NULL);
    hdr->flags &= ~DNS_MASK_RCODE;
    hdr->flags |= ((uint16_t)code & DNS_MASK_RCODE);
}

static dns_pkt_type_t packet_type(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);

    return (hdr->flags & DNS_FLAG_QR)
        ? DNS_PKT_RESPONSE
        : DNS_PKT_QUERY;
}

static dns_op_t query_type(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (dns_op_t)((hdr->flags & DNS_MASK_OPCODE) >> 11);
}

static bool is_authoritative_answer(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_AA) != 0;
}

static bool is_truncated(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_TC) != 0;
}

static bool is_recursion_desired(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_RD) != 0;
}

static bool is_recursion_available(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_RA) != 0;
}

static dns_rcode_t response_code(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (dns_rcode_t)(hdr->flags & DNS_MASK_RCODE);
}

typedef struct {
    const char *qname;
    uint16_t   qtype;
    uint16_t   qclass;
} dns_question_t;

typedef enum {
    DNS_QTYPE_A    = 1,
    DNS_QTYPE_MX   = 15,
    DNS_QTYPE_AAAA = 28,
    DNS_QTYPE_NOT_IMPLEMENTED
} dns_qtype_t;

typedef enum {
    DNS_QCLASS_IN = 1,
    DNS_QCLASS_NOT_IMPLEMENTED
} dns_qclass_t;

static dns_qtype_t question_type(const dns_question_t *question)
{
    assert(question != NULL);
    return (dns_qtype_t)question->qtype;
}

static dns_qclass_t question_class(const dns_question_t *question)
{
    assert(question != NULL);
    return (dns_qclass_t)question->qclass;
}

#endif //DNS_PACKET_H

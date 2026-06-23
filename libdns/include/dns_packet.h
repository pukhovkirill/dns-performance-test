// dns_packet.h
#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Fixed size of a standard DNS protocol header in bytes.
 */
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

/**
 * @brief Standard RFC 1035 DNS header layout.
 *
 * @var id      Transaction ID used to match queries with responses.
 * @var flags   Packed 16-bit field representing all protocol control flags.
 * @var qdcount Number of entries in the question section.
 * @var ancount Number of resource records in the answer section.
 * @var nscount Number of name server resource records in the authority records section.
 * @var arcount Number of resource records in the additional records section.
 */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

/**
 * @brief Identifies whether the packet is a query or a response.
 */
typedef enum {
    DNS_PKT_QUERY    = 0,
    DNS_PKT_RESPONSE = 1
} dns_pkt_type_t;

/**
 * @brief DNS operation codes (OPCODE).
 */
typedef enum {
    DNS_OP_QUERY  = 0,
    DNS_OP_IQUERY = 1,
    DNS_OP_STATUS = 2
} dns_op_t;

/**
 * @brief DNS response error status classifications (RCODE).
 */
typedef enum {
    DNS_RCODE_NO_ERROR        = 0,
    DNS_RCODE_FORMAT_ERROR    = 1,
    DNS_RCODE_SERVER_FAILURE  = 2,
    DNS_RCODE_NAME_ERROR      = 3,
    DNS_RCODE_NOT_IMPLEMENTED = 4,
    DNS_RCODE_REFUSED         = 5
} dns_rcode_t;

/**
 * @brief Sets the packet type flag (Query vs Response) in the header.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 * @param[in] type The packet type classification to apply.
 */
static void dns_set_packet_type(dns_hdr_t *hdr, dns_pkt_type_t type)
{
    assert(hdr != NULL);
    if (type == DNS_PKT_RESPONSE)
        hdr->flags |= DNS_FLAG_QR;
    else
        hdr->flags &= ~DNS_FLAG_QR;
}

/**
 * @brief Configures the operation type (OPCODE) field in the header flags.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 * @param[in] op The operational command value to set.
 */
static void dns_set_query_type(dns_hdr_t *hdr, dns_op_t op)
{
    assert(hdr != NULL);
    hdr->flags &= ~DNS_MASK_OPCODE;
    hdr->flags |= ((uint16_t)op << 11) & DNS_MASK_OPCODE;
}

/**
 * @brief Enables the Authoritative Answer flag in the header flags.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 */
static void dns_set_authoritative_answer(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_AA;
}

/**
 * @brief Enables the TrunCation flag, indicating the message exceeds buffer limits.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 */
static void dns_set_truncated(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_TC;
}

/**
 * @brief Enables the Recursion Desired flag to request recursive resolution.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 */
static void dns_set_recursion_desired(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_RD;
}

/**
 * @brief Enables the Recursion Available flag to denote recursive support.
 *
 * @param[in,out] hdr Pointer to the DNS header.
 */
static void dns_set_recursion_available(dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    hdr->flags |= DNS_FLAG_RA;
}

/**
 * @brief Sets the error response code (RCODE) field in the header flags.
 *
 * @param[in,out] hdr  Pointer to the DNS header.
 * @param[in] code The response error classification to apply.
 */
static void dns_set_response_code(dns_hdr_t *hdr, dns_rcode_t code)
{
    assert(hdr != NULL);
    hdr->flags &= ~DNS_MASK_RCODE;
    hdr->flags |= ((uint16_t)code & DNS_MASK_RCODE);
}

/**
 * @brief Extracts the packet type (Query vs Response) from the header flags.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return The packet type classification.
 */
static dns_pkt_type_t packet_type(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);

    return (hdr->flags & DNS_FLAG_QR)
        ? DNS_PKT_RESPONSE
        : DNS_PKT_QUERY;
}

/**
 * @brief Extracts the operation type (OPCODE) from the header flags.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return The operational command value.
 */
static dns_op_t query_type(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (dns_op_t)((hdr->flags & DNS_MASK_OPCODE) >> 11);
}

/**
 * @brief Checks if the response originates from an authoritative name server.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return True if authoritative, false otherwise.
 */
static bool is_authoritative_answer(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_AA) != 0;
}

/**
 * @brief Checks if the DNS message was truncated due to buffer limits.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return True if truncated, false otherwise.
 */
static bool is_truncated(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_TC) != 0;
}

/**
 * @brief Checks if the client requested recursive resolution.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return True if recursion is desired, false otherwise.
 */
static bool is_recursion_desired(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_RD) != 0;
}

/**
 * @brief Checks if the responding server supports recursive queries.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return True if recursion is available, false otherwise.
 */
static bool is_recursion_available(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (hdr->flags & DNS_FLAG_RA) != 0;
}

/**
 * @brief Extracts the error response code (RCODE) from the header flags.
 *
 * @param[in] hdr Pointer to the DNS header.
 * @return The response error classification.
 */
static dns_rcode_t response_code(const dns_hdr_t *hdr)
{
    assert(hdr != NULL);
    return (dns_rcode_t)(hdr->flags & DNS_MASK_RCODE);
}

/**
 * @brief Represents a single parsed question entry from the query section.
 *
 * @var qname Pointer to a string representing the queried domain name.
 * @var qtype The query category identifier code.
 * @var qclass The protocol family class identifier code.
 */
typedef struct {
    const char *qname;
    uint16_t   qtype;
    uint16_t   qclass;
} dns_question_t;

/**
 * @brief Supported DNS resource record types.
 */
typedef enum {
    DNS_QTYPE_A    = 1,
    DNS_QTYPE_MX   = 15,
    DNS_QTYPE_AAAA = 28,
    DNS_QTYPE_NOT_IMPLEMENTED
} dns_qtype_t;

/**
 * @brief Supported DNS protocol classes.
 */
typedef enum {
    DNS_QCLASS_IN = 1,
    DNS_QCLASS_NOT_IMPLEMENTED
} dns_qclass_t;

/**
 * @brief Safely casts and retrieves the type of DNS question entry.
 *
 * @param[in] question Pointer to the question structure.
 * @return The corresponding dns_qtype_t enumeration value.
 */
static dns_qtype_t question_type(const dns_question_t *question)
{
    assert(question != NULL);
    return (dns_qtype_t)question->qtype;
}

/**
 * @brief Safely casts and retrieves the network class of a DNS question entry.
 *
 * @param[in] question Pointer to the question structure.
 * @return The corresponding dns_qclass_t enumeration value.
 */
static dns_qclass_t question_class(const dns_question_t *question)
{
    assert(question != NULL);
    return (dns_qclass_t)question->qclass;
}

#endif //DNS_PACKET_H

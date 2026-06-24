// dns_builder.c
#include "dns_builder.h"
#include "dns_packet.h"
#include "dns_utils.h"
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

static uint16_t gen_id();
static ssize_t  write_raw_hdr(uint8_t *dst, size_t dst_sz, const dns_hdr_t *hdr);
static ssize_t  write_raw_question(uint8_t *dst, size_t dst_sz, const dns_question_t *qst);

ssize_t dns_build_query(uint8_t *dst, const size_t dst_sz, const dns_query_t q)
{
    if (dst == NULL)
        return BUILD_ERR_NULLPTR;

    dns_hdr_t hdr = {0};

    hdr.id      = gen_id();
    hdr.qdcount = 1;

    dns_set_packet_type(&hdr, DNS_PKT_QUERY);
    dns_set_query_type(&hdr, DNS_OP_QUERY);

    ssize_t write_bytes = 0;
    ssize_t res = write_raw_hdr(dst, dst_sz, &hdr);

    if (res < 0)
        return res;

    write_bytes += res;

    dns_question_t qst = {0};
    qst.qname  = q.domain;
    qst.qtype  = q.qtype;
    qst.qclass = q.qclass;

    res = write_raw_question(
        dst + write_bytes,
        dst_sz - write_bytes,
        &qst
    );

    if (res < 0)
        return res;

    write_bytes += res;

    return write_bytes;
}

ssize_t dns_pkt_to_response(uint8_t *pkt, const size_t pkt_sz)
{
    if (pkt == NULL)
        return BUILD_ERR_NULLPTR;

    // array length must be at least 4 bytes
    if (pkt_sz < 2 * sizeof(uint16_t))
        return BUILD_ERR_BUFSIZE;

    uint8_t *ptr = pkt+2;
    dns_hdr_t hdr = {0};

    hdr.flags = dns_read_u16(ptr);
    dns_set_packet_type(&hdr, DNS_PKT_RESPONSE);
    dns_write_u16(ptr,  hdr.flags);

    return BUILD_OK;
}

uint16_t gen_id()
{
    static int32_t counter = -1;

    if (counter == -1) {
        srand((unsigned int)time(NULL));
        counter = (uint16_t) ((rand() << 8) ^ rand());
        return counter;
    }

    ++counter;
    return counter;
}

ssize_t write_raw_hdr(uint8_t *dst, const size_t dst_sz, const dns_hdr_t *hdr)
{
    assert(dst != NULL);
    assert(hdr != NULL);

    if (dst_sz < DNS_HDR_LEN)
        return BUILD_ERR_BUFSIZE;

    uint8_t *ptr = dst;
    ptr += dns_write_u16(ptr, hdr->id);
    ptr += dns_write_u16(ptr, hdr->flags);
    ptr += dns_write_u16(ptr, hdr->qdcount);
    ptr += dns_write_u16(ptr, hdr->ancount);
    ptr += dns_write_u16(ptr, hdr->nscount);
    ptr += dns_write_u16(ptr, hdr->arcount);

    assert((size_t)(ptr - dst) == DNS_HDR_LEN);

    return DNS_HDR_LEN;
}

static bool end_with_dot(const char *domain, const size_t len)
{
    assert(domain != NULL);
    if (len == 0)
        return false;
    return domain[len - 1] == '.';
}

static size_t question_size(const dns_question_t *sec)
{
    assert(sec != NULL);

    size_t sz = 0;

    // add an extra byte if the domain name
    // does not end with a dot.
    sz += strlen(sec->qname);
    sz += (size_t)!end_with_dot(sec->qname, sz);

    sz += sizeof(sec->qtype);
    sz += sizeof(sec->qclass);

    // +2 due to the label from beginning and
    // end of the `qname` field
    sz += 2;

    assert(sz >= 2);

    return sz;
}

ssize_t write_raw_question(uint8_t *dst, const size_t dst_sz, const dns_question_t *qst)
{
    assert(dst != NULL);
    assert(qst != NULL);

    const size_t total_len = question_size(qst);

    if (dst_sz < total_len)
        return BUILD_ERR_BUFSIZE;

    uint8_t len = 0;
    ssize_t write_bytes = 0;
    const char *ch    = qst->qname;
    const char *start = qst->qname;

    /*
     * Convert the standard textual domain name into the wire-format DNS labels.
     * The loop tokenizes the qname string by '.' delimiters and the null terminator.
     * For each segment, it writes a single-byte length prefix to the destination
     * buffer, followed by the actual character data of that label.
     *
     * Encoding example:
     *   Input:  "example.com"
     *   Output: [7]['e']['x']['a']['m']['p']['l']['e'][3]['c']['o']['m'][0]
     */
    while (1) {
        if (*ch == '.' || *ch == '\0') {
            // length prefix and text to destination
            if (len > 0) {
                dst[write_bytes++] = len;
                memcpy(dst + write_bytes, start, len);
                write_bytes += len;
            }
            if (*ch == '\0')
                break;
            len = 0;
            start = ch + 1;
        }
        else {
            ++len;
        }
        ++ch;
    }
    dst[write_bytes++] = 0;

    len = sizeof(qst->qtype) + sizeof(qst->qclass);
    memcpy(dst + write_bytes, &qst->qtype, len);
    write_bytes += len;

    assert((size_t)write_bytes == total_len);
    return write_bytes;
}

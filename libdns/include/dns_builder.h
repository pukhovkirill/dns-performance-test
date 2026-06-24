// dns_builder.h
#ifndef DNS_BUILDER_H
#define DNS_BUILDER_H

#include <stdint.h>
#include <sys/types.h>
#include "dns_packet.h"

/**
 * @brief Status and error codes for DNS builder operations.
 */
typedef enum {
    BUILD_OK          =  0,
    BUILD_ERR_NULLPTR = -1,
    BUILD_ERR_BUFSIZE = -2,
    BUILD_ERR_UNKNOWN = -3
} builder_status_t;

/**
 * @brief Configuration parameters for a single DNS query.
 *
 * @var domain Pointer to a null-terminated string containing the target domain name.
 * @var qtype The DNS query type (e.g., A, AAAA, MX, TXT).
 * @var qclass The DNS query class (typically IN for Internet).
 */
typedef struct {
    const char   *domain;
    dns_qtype_t  qtype;
    dns_qclass_t qclass;
} dns_query_t;

/**
 * @brief Builds a DNS query packet in wire format.
 *
 * @param[out] dst Destination buffer where the raw packet bytes (in Network Byte Order) will be written.
 * @param[in] dst_sz Maximum capacity of the destination buffer in bytes.
 * @param[in] q Query settings configuration.
 * @return The number of bytes written to the @p dst buffer on success (>0),
 *         or a negative error code (<0) on failure.
 */
ssize_t dns_build_query(
    uint8_t *dst,
    size_t dst_sz,
    dns_query_t q
);

/**
 * @brief In-place converts a DNS request packet into a valid response packet stub.
 *
 * Modifies the packet header flags (flipping QR bit to 1)
 * to transform an incoming query into an outgoing response.
 *
 * @param[in,out] pkt Pointer to the raw DNS packet buffer (with Network Byte Order).
 * @param[in] pkt_sz Total size of the packet data inside the buffer.
 * @return A status code.
 */
ssize_t dns_pkt_to_response(
    uint8_t *pkt,
    size_t pkt_sz
);

/**
 * @brief Converts a numeric return code or byte size into a builder_status_t.
 *
 * Evaluates the return code to determine the build status. Any positive value
 * or value less than 1 will result in an unknown error status, except for zero.
 *
 * @param[in] code The return code (negative error) or number of bytes (positive/zero).
 * @return BUILD_OK if the code is exactly 0.
 *         BUILD_ERR_UNKNOWN if the code is unknown.
 */
static builder_status_t get_build_status(const ssize_t code)
{
    if (code >= 0)
        return BUILD_OK;
    if (code < BUILD_ERR_UNKNOWN)
        return BUILD_ERR_UNKNOWN;
    return (builder_status_t)code;
}

#endif //DNS_BUILDER_H

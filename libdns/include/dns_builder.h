// dns_builder.h
#ifndef DNS_BUILDER_H
#define DNS_BUILDER_H

#include <stdint.h>
#include <sys/types.h>
#include "dns_packet.h"

typedef enum {
    BUILD_OK          =  0,
    BUILD_ERR_NULLPTR = -1,
    BUILD_ERR_BUFSIZE = -2,
    BUILD_ERR_UNKNOWN = -3
} builder_status_t;

typedef struct {
    const char   *domain;
    dns_qtype_t  qtype;
    dns_qclass_t qclass;
} dns_query_t;

ssize_t dns_build_query(
    uint8_t *dst,
    size_t dst_sz,
    dns_query_t q
);

ssize_t dns_pkt_to_response(
    uint8_t *pkt,
    size_t pkt_sz
);

static builder_status_t get_build_status(const ssize_t code)
{
    if (code >= 0)
        return BUILD_OK;
    if (code < BUILD_ERR_UNKNOWN)
        return BUILD_ERR_UNKNOWN;
    return (builder_status_t)code;
}

#endif //DNS_BUILDER_H

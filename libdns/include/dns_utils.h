// dns_utils.h
#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include "dns_packet.h"

size_t dns_write_u16(uint8_t *dst, uint16_t value);
uint16_t dns_read_u16(const uint8_t *src);

#endif //DNS_UTILS_H
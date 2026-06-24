// dns_utils.c
#include "dns_utils.h"
#include <string.h>
#include <netinet/in.h>

size_t dns_write_u16(uint8_t *dst, uint16_t value)
{
    value = htons(value);
    memcpy(dst, &value, sizeof(value));
    return sizeof(value);
}

uint16_t dns_read_u16(const uint8_t *src)
{
    uint16_t value;
    memcpy(&value, src, sizeof(value));
    return ntohs(value);
}

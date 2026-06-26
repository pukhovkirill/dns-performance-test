// dns_utils.c
#include "dns_utils.h"
#include <string.h>
#include <netinet/in.h>

typedef struct {
    const char *name;
    dns_qtype_t value;
} dns_qtype_map_t;

/*
 * Internal mapping table for converting textual DNS query
 *        type names into protocol enum values.
 *
 * The table is automatically generated from DNS_QTYPE_LIST declared
 * in dns_packet.h using X-Macro expansion.
 *
 * This ensures that enum definitions and string mappings remain
 * synchronized automatically whenever a new DNS query type is added,
 * eliminating duplicated manual updates in multiple files.
 */
static const dns_qtype_map_t qtype_map[] = {
#define X_GEN_MAP(name_str, enum_val, num) { name_str, enum_val },
    DNS_QTYPE_LIST(X_GEN_MAP)
#undef X_GEN_MAP
};


// number of entries available in the generated DNS type map.
#define QTYPE_MAP_SIZE (sizeof(qtype_map) / sizeof(qtype_map[0]))


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

dns_qtype_t str_to_dns_qtype(const char *str, const uint8_t len)
{
    if (str == NULL)
        return DNS_QTYPE_NOT_IMPLEMENTED;

    for (size_t i = 0; i < QTYPE_MAP_SIZE; i++) {
        const char *name = qtype_map[i].name;

        if (strlen(name) == len &&
            memcmp(name, str, len) == 0)
        {
            return qtype_map[i].value;
        }
    }

    return DNS_QTYPE_NOT_IMPLEMENTED;
}

size_t dns_qname_encoded_size(const char *domain)
{
    if (domain == NULL)
        return 0;

    const size_t len = strlen(domain);

    if (len == 0)
        return 0;

    if (domain[len - 1] == '.')
        return len + 1;

    return len + 2;
}
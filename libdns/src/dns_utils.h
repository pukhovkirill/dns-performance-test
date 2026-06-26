// dns_utils.h
#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include "dns_packet.h"

/**
 * @brief Writes a 16-bit integer in Network Byte Order (Big-Endian) to a destination buffer.
 *
 * @param[out] dst Pointer to the destination buffer (must be at least 2 bytes long).
 * @param[in] value The 16-bit value in host byte order to be written.
 */
size_t dns_write_u16(uint8_t *dst, uint16_t value);

/**
 * @brief Reads a 16-bit integer from Network Byte Order (Big-Endian) from a source buffer.
 *
 * @param[in] src Pointer to the source buffer (must be at least 2 bytes long).
 * @return The decoded 16-bit integer in host byte order.
 */
uint16_t dns_read_u16(const uint8_t *src);

/**
 * @brief Converts a textual DNS query type representation into its corresponding enum value.
 *
 * Matches known DNS record type strings (for example: "A", "MX", "AAAA")
 * and returns the associated dns_qtype_t constant.
 *
 * @param[in] str Pointer to the query type string.
 * @param[in] len Length of the string to compare.
 * @return Matching dns_qtype_t value, or DNS_QTYPE_NOT_IMPLEMENTED
 *         if the type is not recognized.
 */
dns_qtype_t str_to_dns_qtype(const char *str, uint8_t len);

/**
 * @brief Calculates the encoded size of a domain name in DNS wire format.
 *
 * Computes the number of bytes required to store the domain name
 * in label-length encoded DNS format as used in the question section.
 *
 * @note The input string must be a valid null-terminated C string.
 *
 * Example:
 *   "google.com"  -> 12 bytes  ([6]google[3]com[0])
 *   "google.com." -> 12 bytes  ([6]google[3]com[0])
 *
 * @param[in] domain Null-terminated domain name string.
 * @return Required size in bytes for DNS wire format encoding.
 */
size_t dns_qname_encoded_size(const char *domain);

#endif //DNS_UTILS_H
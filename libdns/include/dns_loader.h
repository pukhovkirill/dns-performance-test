// dns_loader.h
#ifndef DNS_LOADER_H
#define DNS_LOADER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct qiter_list qiter_list_t;

/**
 * @brief Contiguous storage for serialized DNS query packets and their metadata.
 *
 * @note Because metadata may reference the data buffer, metadata must be
 *       destroyed before data is freed.
 *
 * @var data Contiguous buffer containing DNS query packets.
 * @var metadata Packet metadata referencing entries in data.
 */
typedef struct {
    uint8_t      *data;
    qiter_list_t *metadata;
} packet_array_t;

/**
 * @brief Status and error codes for DNS queries loader operations.
 */
typedef enum {
    LOAD_OK            =  0,
    LOAD_ERR_NULLPTR   = -1,
    LOAD_ERR_NOFILE    = -2,
    LOAD_ERR_OPENFILE  = -3,
    LOAD_ERR_READFILE  = -4,
    LOAD_ERR_BADFORMAT = -5,
    LOAD_ERR_BUFSIZE   = -6,
    LOAD_ERR_ALLOC     = -7,
    LOAD_ERR_UNKNOWN   = -8
} loader_status_t;

/**
 * @brief Loads and serializes DNS queries from a text file.
 *
 * Reads DNS queries from @p filename, serializes each valid query into the
 * contiguous buffer owned by @p dst, and creates metadata describing the
 * resulting packets.
 *
 * Each input line is expected to contain a DNS query type followed by a domain
 * name, separated by one or more spaces.
 *
 * @note Invalid lines are ignored.
 *
 * @param[out] dst Destination packet array.
 * @param[in] filename Path to the input text file.
 * @return Number of successfully loaded DNS queries (0>=)
 *         or a negative error code (<0) on failure.
 */
ssize_t load_dns_queries_from_file(
    packet_array_t *dst,
    const char *filename
);

/**
 * @brief Releases all resources owned by a packet array.
 *
 * @param[in,out] array Packet array to destroy, or NULL.
 * @note This function does not free the packet_array_t object itself.
 */
void packet_array_destroy(packet_array_t *array);

/**
 * @brief Converts a numeric return code or byte size into a loader_status_t.
 *
 * Evaluates the return code to determine the load status. Any positive value
 * or value less than 1 will result in an unknown error status, except for zero.
 *
 * @param[in] code The return code (negative error) or number of bytes (positive/zero).
 * @return LOAD_OK if the code is exactly 0.
 *         LOAD_ERR_UNKNOWN if the code is greater than 0 or less than 1.
 */
static loader_status_t get_load_status(const ssize_t code)
{
    if (code >= 0)
        return LOAD_OK;
    if (code < LOAD_ERR_UNKNOWN)
        return LOAD_ERR_UNKNOWN;
    return (loader_status_t)code;
}

#endif //DNS_LOADER_H
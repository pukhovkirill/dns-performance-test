// dns_iterator.h
#ifndef DNS_ITERATOR_H
#define DNS_ITERATOR_H

#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Metadata representation of a single DNS query entry.
 *
 * @var pkt Pointer to the raw packet bytes.
 * @var pkt_len Length of the packet in bytes.
 */
typedef struct {
    const uint8_t *pkt;
    size_t pkt_len;
} qiter_entry;

/**
 * @brief Shared buffer list storing registered DNS query entries.
 *        The inner fields are encapsulated and hidden from the user.
 */
typedef struct qiter_list qiter_list_t;

/**
 * @brief Context structure for iterating over a DNS query list.
 *        The inner fields are encapsulated and hidden from the user.
 */
typedef struct qiterator qiter_t;

/**
 * @brief Allocates and initializes a new query list instance in heap.
 *
 * @param[in] count Maximum number of query entries the list can hold.
 * @return Pointer to the allocated list on success, or NULL on allocation/input failure.
 */
qiter_list_t *qiter_list_create(
    size_t count
);

/**
 * @brief Creates and initializes a new query iterator bound to a shared query list.
 *
 * @param[in] shrd_list Pointer to the populated shared list instance to traverse.
 * @return Pointer to the allocated iterator on success, or NULL on validation/allocation failure.
 */
qiter_t *qiter_create(
    qiter_list_t *shrd_list
);

/**
 * @brief Registers a new DNS query packet entry into the list.
 *
 * Appends the packet metadata to the internal elements array by copying the
 * entry structure value if the capacity threshold has not been exceeded.
 *
 * @param[in,out] list Pointer to the shared query list.
 * @param[in] pkt Pointer to the raw data.
 * @param[in] pkt_len Length of the raw data.
 */
void qiter_list_register(
    qiter_list_t *list,
    const uint8_t *pkt,
    size_t pkt_len
);

/**
 * @brief Retrieves the current entry and advances the iterator position.
 *
 * This implementation wraps around to 0 using an efficient pointer increment
 * when reaching the end of the registered items array.
 *
 * @param[in,out] iter Pointer to the active iterator tracking structure.
 * @return The current qiter_entry data block, or an empty entry structure on failure.
 */
qiter_entry qiter_next(qiter_t *iter);

/**
 * @brief Frees all dynamically allocated memory resources of the iterator context.
 *
 * @param[in,out] iter Pointer to the iterator instance to destroy.
 */
void qiter_destroy(qiter_t *iter);

/**
 * @brief Frees all dynamically allocated memory resources of the shared query list.
 *
 * @param[in,out] list Pointer to the shared query list to destroy.
 */
void qiter_list_destroy(qiter_list_t *list);

#endif //DNS_ITERATOR_H

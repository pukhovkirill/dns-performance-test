// dns_iterator.h
#ifndef DNS_ITERATOR_H
#define DNS_ITERATOR_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const uint8_t *pkt;
    size_t pkt_len;
} qiter_entry;

typedef struct qiter_list qiter_list_t;

typedef struct qiterator qiter_t;

qiter_list_t *qiter_list_create(
    size_t count
);

qiter_t *qiter_create(
    qiter_list_t *shrd_list
);

void qiter_list_register(
    qiter_list_t *list,
    const uint8_t *pkt,
    size_t pkt_len
);

qiter_entry qiter_next(qiter_t *iter);

void qiter_destroy(qiter_t *iter);

void qiter_list_destroy(qiter_list_t *list);

#endif //DNS_ITERATOR_H

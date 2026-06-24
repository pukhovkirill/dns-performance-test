// dns_iterator.c
#include "dns_iterator.h"

struct qiter_list {
    qiter_entry *entries;
    size_t capacity;
    size_t count;
};

struct qiterator {
    qiter_list_t *list;
    size_t pos;
};

qiter_list_t *qiter_list_create(const size_t count)
{

}

qiter_t *qiter_create(qiter_list_t *shrd_list)
{

}

void qiter_list_register(qiter_list_t *list, const uint8_t *pkt, const size_t pkt_len)
{

}

qiter_entry qiter_next(qiter_t *iter)
{

}

void qiter_destroy(qiter_t *iter)
{

}

void qiter_list_destroy(qiter_list_t *list)
{

}

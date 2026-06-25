// dns_iterator.c
#include "dns_iterator.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

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
    if (count == 0)
        return NULL;

    qiter_list_t *list = malloc(sizeof(struct qiter_list));
    if (list == NULL)
        return NULL;

    list->entries = malloc(count * sizeof(*list->entries));
    if (list->entries == NULL) {
        free(list);
        return NULL;
    }

    list->count    = 0;
    list->capacity = count;

    return list;
}

qiter_t *qiter_create(qiter_list_t *shrd_list)
{
    if (shrd_list == NULL          ||
        shrd_list->entries == NULL ||
        shrd_list->capacity == 0)
        return NULL;

    if (shrd_list->count == 0)
        return NULL;

    qiter_t *iter = malloc(sizeof(struct qiterator));
    if (iter == NULL)
        return NULL;

    iter->list = shrd_list;
    iter->pos  = 0;

    return iter;
}

void qiter_list_register(
    qiter_list_t *list,
    const uint8_t *pkt,
    const size_t pkt_len
)
{
    if (list == NULL || list->entries == NULL)
        return;

    if (pkt == NULL)
        return;

    qiter_entry entry = {0};
    entry.pkt     = pkt;
    entry.pkt_len = pkt_len;

    if (list->count < list->capacity)
        list->entries[list->count++] = entry;
}

qiter_entry qiter_next(qiter_t *iter)
{
    assert(iter != NULL);
    assert(iter->list != NULL);
    assert(iter->list->entries != NULL);
    assert(iter->list->count > 0);

    const qiter_entry entry =
        iter->list->entries[iter->pos];

    iter->pos++;
    if (iter->pos >= iter->list->count)
        iter->pos = 0;

    return entry;
}

void qiter_destroy(qiter_t *iter)
{
    if (iter != NULL) {
        free(iter);
    }
}

void qiter_list_destroy(qiter_list_t *list)
{
    if (list != NULL) {
        free(list->entries);
        free(list);
    }
}

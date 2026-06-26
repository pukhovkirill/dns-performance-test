// test_dns_iterator.c
#include "dns_iterator.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define RUN_TEST(test_function) \
    do {                                           \
        test_function();                           \
        printf("[ PASSED ] %s\n", #test_function); \
    } while (0)

static void test_qiter_list_create_zero_capacity(void)
{
    qiter_list_t *list = qiter_list_create(0);

    assert(list == NULL);
}

static void test_qiter_list_create_valid_capacity(void)
{
    qiter_list_t *list = qiter_list_create(3);

    assert(list != NULL);

    qiter_list_destroy(list);
}

static void test_qiter_create_null_list(void)
{
    qiter_t *iter = qiter_create(NULL);

    assert(iter == NULL);
}

static void test_qiter_create_empty_list(void)
{
    qiter_list_t *list = qiter_list_create(3);

    assert(list != NULL);

    qiter_t *iter = qiter_create(list);

    assert(iter == NULL);

    qiter_list_destroy(list);
}

static void test_qiter_create_after_register(void)
{
    static const uint8_t packet[] = {
        0x12, 0x34, 0x01, 0x00
    };

    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(
        list,
        packet,
        sizeof(packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_next_single_entry(void)
{
    static const uint8_t packet[] = {
        0x12, 0x34, 0x01, 0x00
    };

    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(
        list,
        packet,
        sizeof(packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == packet);
    assert(entry.pkt_len == sizeof(packet));

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_next_preserves_packet_pointer(void)
{
    uint8_t packet[] = {
        0xAA, 0xBB, 0xCC
    };

    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(
        list,
        packet,
        sizeof(packet)
    );

    packet[0] = 0xFF;

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == packet);
    assert(entry.pkt[0] == 0xFF);
    assert(entry.pkt_len == sizeof(packet));

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_next_multiple_entries(void)
{
    static const uint8_t first_packet[] = {
        0x01, 0x02
    };

    static const uint8_t second_packet[] = {
        0x03, 0x04, 0x05
    };

    static const uint8_t third_packet[] = {
        0x06, 0x07, 0x08, 0x09
    };

    qiter_list_t *list = qiter_list_create(3);

    assert(list != NULL);

    qiter_list_register(
        list,
        first_packet,
        sizeof(first_packet)
    );

    qiter_list_register(
        list,
        second_packet,
        sizeof(second_packet)
    );

    qiter_list_register(
        list,
        third_packet,
        sizeof(third_packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == first_packet);
    assert(entry.pkt_len == sizeof(first_packet));

    entry = qiter_next(iter);

    assert(entry.pkt == second_packet);
    assert(entry.pkt_len == sizeof(second_packet));

    entry = qiter_next(iter);

    assert(entry.pkt == third_packet);
    assert(entry.pkt_len == sizeof(third_packet));

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_next_wraps_around(void)
{
    static const uint8_t first_packet[] = {
        0x10
    };

    static const uint8_t second_packet[] = {
        0x20
    };

    qiter_list_t *list = qiter_list_create(2);

    assert(list != NULL);

    qiter_list_register(
        list,
        first_packet,
        sizeof(first_packet)
    );

    qiter_list_register(
        list,
        second_packet,
        sizeof(second_packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    qiter_entry entry = qiter_next(iter);
    assert(entry.pkt == first_packet);

    entry = qiter_next(iter);
    assert(entry.pkt == second_packet);

    /*
     * After the last element, the iterator
     * must return to the first one.
     */
    entry = qiter_next(iter);
    assert(entry.pkt == first_packet);

    entry = qiter_next(iter);
    assert(entry.pkt == second_packet);

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_list_register_respects_capacity(void)
{
    static const uint8_t first_packet[] = {
        0x01
    };

    static const uint8_t second_packet[] = {
        0x02
    };

    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(
        list,
        first_packet,
        sizeof(first_packet)
    );

    /*
     * This packet must not be added because
     * the list's capacity has already been exhausted.
     */
    qiter_list_register(
        list,
        second_packet,
        sizeof(second_packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == first_packet);
    assert(entry.pkt_len == sizeof(first_packet));

    /*
     * Only the first element remains in the list,
     * so the next call will return it again.
     */
    entry = qiter_next(iter);

    assert(entry.pkt == first_packet);
    assert(entry.pkt_len == sizeof(first_packet));

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_list_register_null_list(void)
{
    static const uint8_t packet[] = {
        0x01, 0x02, 0x03
    };

    // The function should not crash.
    qiter_list_register(
        NULL,
        packet,
        sizeof(packet)
    );
}

static void test_qiter_list_register_null_packet(void)
{
    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(list, NULL, 10);

    // The NULL packet must not be registered.
    qiter_t *iter = qiter_create(list);

    assert(iter == NULL);

    qiter_list_destroy(list);
}

static void test_qiter_list_register_zero_packet_length(void)
{
    static const uint8_t packet[] = { 0x01 };

    qiter_list_t *list = qiter_list_create(1);

    assert(list != NULL);

    qiter_list_register(list, packet, 0);

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    const qiter_entry entry = qiter_next(iter);

    assert(entry.pkt == packet);
    assert(entry.pkt_len == 0);

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_multiple_iterators_are_independent(void)
{
    static const uint8_t first_packet[] = { 0x11 };

    static const uint8_t second_packet[] = { 0x22 };

    qiter_list_t *list = qiter_list_create(2);

    assert(list != NULL);

    qiter_list_register(
        list,
        first_packet,
        sizeof(first_packet)
    );

    qiter_list_register(
        list,
        second_packet,
        sizeof(second_packet)
    );

    qiter_t *first_iter = qiter_create(list);
    qiter_t *second_iter = qiter_create(list);

    assert(first_iter != NULL);
    assert(second_iter != NULL);

    // Both iterators must start at position 0.
    qiter_entry entry = qiter_next(first_iter);
    assert(entry.pkt == first_packet);

    entry = qiter_next(first_iter);
    assert(entry.pkt == second_packet);

    /*
     * Advancing the first iterator must
     * not change the position of the second.
     */
    entry = qiter_next(second_iter);
    assert(entry.pkt == first_packet);

    entry = qiter_next(second_iter);
    assert(entry.pkt == second_packet);

    qiter_destroy(first_iter);
    qiter_destroy(second_iter);
    qiter_list_destroy(list);
}

static void test_iterator_uses_registered_packet_lengths(void)
{
    static const uint8_t first_packet[] = {
        0x01, 0x02, 0x03
    };

    static const uint8_t second_packet[] = {
        0x04, 0x05, 0x06, 0x07, 0x08
    };

    qiter_list_t *list = qiter_list_create(2);

    assert(list != NULL);

    qiter_list_register(
        list,
        first_packet,
        sizeof(first_packet)
    );

    qiter_list_register(
        list,
        second_packet,
        sizeof(second_packet)
    );

    qiter_t *iter = qiter_create(list);

    assert(iter != NULL);

    qiter_entry entry = qiter_next(iter);

    assert(entry.pkt_len == 3);

    entry = qiter_next(iter);

    assert(entry.pkt_len == 5);

    qiter_destroy(iter);
    qiter_list_destroy(list);
}

static void test_qiter_destroy_null(void)
{
    qiter_destroy(NULL);
}

static void test_qiter_list_destroy_null(void)
{
    qiter_list_destroy(NULL);
}

void test_dns_iterator_all(void)
{
    printf("========================================\n");
    printf("Running dns_iterator.h tests\n");
    printf("========================================\n");

    RUN_TEST(test_qiter_list_create_zero_capacity);
    RUN_TEST(test_qiter_list_create_valid_capacity);

    RUN_TEST(test_qiter_create_null_list);
    RUN_TEST(test_qiter_create_empty_list);
    RUN_TEST(test_qiter_create_after_register);

    RUN_TEST(test_qiter_next_single_entry);
    RUN_TEST(test_qiter_next_preserves_packet_pointer);
    RUN_TEST(test_qiter_next_multiple_entries);
    RUN_TEST(test_qiter_next_wraps_around);

    RUN_TEST(test_qiter_list_register_respects_capacity);
    RUN_TEST(test_qiter_list_register_null_list);
    RUN_TEST(test_qiter_list_register_null_packet);
    RUN_TEST(test_qiter_list_register_zero_packet_length);

    RUN_TEST(test_multiple_iterators_are_independent);
    RUN_TEST(test_iterator_uses_registered_packet_lengths);

    RUN_TEST(test_qiter_destroy_null);
    RUN_TEST(test_qiter_list_destroy_null);

    printf("========================================\n");
    printf("All dns_iterator.h tests passed\n");
    printf("========================================\n");
}
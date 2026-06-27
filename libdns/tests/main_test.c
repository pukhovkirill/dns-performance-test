// main_test.c
#include <stdio.h>

void test_dns_packet_all(void);
void test_dns_builder_all(void);
void test_dns_iterator_all(void);
void test_dns_loader_all(void);
void test_dns_utils_all(void);

int main(void) {
    printf("Running all tests...\n");

    test_dns_packet_all();
    test_dns_builder_all();
    test_dns_iterator_all();
    test_dns_loader_all();
    test_dns_utils_all();

    printf("All tests passed!\n");
    return 0;
}
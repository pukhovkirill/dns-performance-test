# libdns

A small C library for building DNS query packets in wire format and loading query lists from text files. It is part of the `dns-performance-test` project and provides the low-level DNS encoding layer used by the benchmark tool.

The library targets RFC 1035 query construction.

Build artifacts are placed in `../build/libdns/`:

- `libdns.a` — static library
- `libdns_run_tests` — test executable

## Building

From the project root:

```bash
make -C libdns          # build the static library
make -C libdns test     # build and run tests
```

Or from inside `libdns/`:

```bash
make
make test
```

Compiler flags: C99, `-Wall -Wextra -O2`.

To link against the library in another target:

```bash
gcc my_app.c -Ilibdns/include -Lbuild/libdns -ldns -o my_app
```

## Modules

### dns_packet

Defines the core DNS protocol types used across the library.

- `dns_hdr_t` — 12-byte header (ID, flags, section counts).
- Flag constants: `DNS_FLAG_QR`, `DNS_FLAG_AA`, `DNS_FLAG_TC`, `DNS_FLAG_RD`, `DNS_FLAG_RA`.
- Enums for packet type (`DNS_PKT_QUERY` / `DNS_PKT_RESPONSE`), opcode, and response code (RCODE).
- `dns_question_t` — parsed question section fields (qname, qtype, qclass).
- Supported query types: `A` (1), `MX` (15), `AAAA` (28). Types are declared via the `DNS_QTYPE_LIST` X-macro so enum values and string mappings stay in sync.
- Supported query class: `DNS_QCLASS_IN` (Internet).

The header also provides inline helpers to set and read flags, for example `dns_set_packet_type()`, `dns_set_recursion_desired()`, `packet_type()`, `response_code()`, and others. These operate on host-order `dns_hdr_t` structures, not on raw wire bytes.

### dns_builder

Builds DNS query packets and converts queries into minimal response stubs.

**Key types**

- `dns_query_t` — input for building a query: domain name, qtype, qclass.
- `builder_status_t` — error codes (`BUILD_OK`, `BUILD_ERR_NULLPTR`, `BUILD_ERR_BUFSIZE`, etc.).

**Functions**

| Function | Description |
|----------|-------------|
| `dns_build_query()` | Writes a complete query packet into a caller-provided buffer. Returns bytes written, or a negative error code. |
| `dns_query_packet_size()` | Returns the exact buffer size needed for a given domain name. |
| `dns_pkt_to_response()` | Flips the QR bit in an existing packet to mark it as a response. Does not add answer records. |

Query construction details:

- Sets `qdcount` to 1; answer/authority/additional counts remain zero.
- Generates a transaction ID: first call seeds a counter from `time()` and `rand()`, then IDs increment sequentially.
- Encodes the domain name in standard label format (`[len][label]...[0]`).
- A trailing dot on the domain name is accepted and does not change the encoded size.
- Writes QTYPE and QCLASS as 16-bit big-endian values.

### dns_utils (internal)

Shared helpers used by the builder and loader. Not included from `dns.h`.

- `dns_write_u16()` / `dns_read_u16()` — network byte order conversion.
- `str_to_dns_qtype()` — maps strings like `"A"`, `"MX"`, `"AAAA"` to `dns_qtype_t`.
- `dns_qname_encoded_size()` — computes wire-format name length for buffer sizing.

### dns_iterator

Manages a fixed-capacity list of query packet references and provides round-robin iteration. This is useful for replaying the same set of queries in a load test.

**Types**

- `qiter_entry` — pointer to a packet buffer and its length.
- `qiter_list_t` — opaque list of entries.
- `qiter_t` — opaque iterator bound to a list.

**Workflow**

1. `qiter_list_create(count)` — allocate a list with a maximum capacity.
2. `qiter_list_register(list, pkt, pkt_len)` — append a packet reference. Silently ignores the call if the list is full, or if `list` or `pkt` is NULL.
3. `qiter_create(list)` — create an iterator. Requires at least one registered entry.
4. `qiter_next(iter)` — return the current entry and advance. Wraps to the first entry after the last one.
5. `qiter_destroy()` / `qiter_list_destroy()` — free resources.

Multiple iterators can share the same list; each keeps its own position.

### dns_loader

Reads a text file, builds wire-format query packets, and stores them in a contiguous buffer with accompanying metadata for iteration.

**Types**

- `packet_array_t` — owns a `data` buffer and a `metadata` list (`qiter_list_t`).
- `loader_status_t` — error codes for file and parsing failures.

**Functions**

| Function | Description |
|----------|-------------|
| `load_dns_queries_from_file()` | Parse a file, allocate buffers, build packets. Returns the number of loaded queries, or a negative error code. |
| `packet_array_destroy()` | Free `data` and `metadata`. Does not free the `packet_array_t` struct itself. |

The loader performs two passes over the file: first to count valid lines and estimate total buffer size, then to build and register packets. Invalid lines are skipped without aborting the load.

**Input file format**

Each non-empty line must contain a query type followed by a domain name, separated by one or more spaces:

```
A example.com
MX mail.example.org
AAAA www.example.net
```

Rules:

- Leading and trailing whitespace on the line is ignored.
- The query type must be one of: `A`, `MX`, `AAAA`.
- The domain must not contain internal spaces.
- Lines that do not match the format are silently skipped.
- Windows-style `\r\n` line endings are handled.
- All queries use class `IN`.

**Error codes**

| Code | Meaning |
|------|---------|
| `LOAD_OK` | Success (also returned by helper `get_load_status()` for non-negative counts) |
| `LOAD_ERR_NULLPTR` | NULL argument |
| `LOAD_ERR_NOFILE` | File does not exist |
| `LOAD_ERR_OPENFILE` | Cannot open file |
| `LOAD_ERR_READFILE` | Read failure |
| `LOAD_ERR_BADFORMAT` | Packet build failed during load |
| `LOAD_ERR_BUFSIZE` | Buffer too small |
| `LOAD_ERR_ALLOC` | Memory allocation failed |

## Usage example

### Build a single query manually

```c
#include "dns.h"

uint8_t buf[512];
dns_query_t q = {
    .domain = "example.com",
    .qtype  = DNS_QTYPE_A,
    .qclass = DNS_QCLASS_IN,
};

ssize_t n = dns_build_query(buf, sizeof(buf), q);
if (n < 0) {
    /* handle error */
}
/* send buf[0..n-1] over UDP port 53 */
```

### Load queries from a file and iterate

```c
#include "dns.h"

packet_array_t array = {0};

ssize_t count = load_dns_queries_from_file(&array, "queries.txt");
if (count < 0) {
    /* handle error */
}

qiter_t *iter = qiter_create(array.metadata);

for (int i = 0; i < count; i++) {
    qiter_entry entry = qiter_next(iter);
    /* send entry.pkt[0..entry.pkt_len-1] */
}

qiter_destroy(iter);
packet_array_destroy(&array);
```

## Tests

The test suite covers all public modules:

- `test_dns_packet.c` — header flag helpers and type definitions
- `test_dns_builder.c` — query encoding, buffer sizing, response conversion
- `test_dns_iterator.c` — list registration, wrap-around, capacity limits
- `test_dns_loader.c` — file parsing, whitespace handling, invalid lines

Run from the project root:

```bash
make test
```

This builds and executes tests for all modules, including libdns.

## Code coverage

The `coverage` target rebuilds libdns with gcov instrumentation, runs the test suite, and generates an HTML report via `lcov` and `genhtml`. Requires `lcov` and a GCC toolchain with gcov support.

From the project root:

```bash
make libdns_coverage   # libdns only
make coverage          # all modules
```

The report is written to `../build/libdns/coverage_reports/html/index.html` (open this file in a browser). The intermediate `coverage.info` file is stored alongside it in `../build/libdns/coverage_reports/`.

## Limitations

- Only query packets are built; response parsing is out of scope.
- Supported record types are limited to A, MX, and AAAA. Unknown types in input files cause the line to be skipped.
- `dns_pkt_to_response()` only sets the QR flag; it does not populate answer sections.
- Transaction IDs are generated locally and are not guaranteed to be cryptographically random.
- The iterator stores pointers into the contiguous `data` buffer; do not free `data` while iterators or metadata still reference it.

## Public API entry point

Include a single header to access all modules:

```c
#include "dns.h"
```
// dns_loader.c
#include "dns_loader.h"
#include "dns_builder.h"
#include "dns_iterator.h"
#include "dns_utils.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool parse_query_line(
    const char *line_start,
    const char *line_end,
    size_t *out_type_len,
    char *out_domain,
    size_t max_domain_len
);
static size_t estimate_valid_queries(const char *buf, size_t *count);
static ssize_t read_file_to_buffer(char **dst, const char *filename);
static ssize_t open_file(FILE **dst, const char *filename);

ssize_t load_dns_queries_from_file(packet_array_t *dst, const char *filename)
{
    if (dst == NULL)
        return LOAD_ERR_NULLPTR;

    if (filename == NULL)
        return LOAD_ERR_NULLPTR;

    assert(dst->data == NULL);
    assert(dst->metadata == NULL);

    char *file_bytes = NULL;
    ssize_t res = read_file_to_buffer(&file_bytes, filename);
    if (res < 0)
        return res;

    size_t count = 0;
    size_t buf_sz = estimate_valid_queries(file_bytes, &count);

    dst->data = malloc(buf_sz);
    if (dst->data == NULL) {
        res = LOAD_ERR_ALLOC;
        goto out;
    }

    dst->metadata = qiter_list_create(count);
    if (dst->metadata == NULL) {
        free(dst->data);
        dst->data = NULL;
        res = LOAD_ERR_ALLOC;
        goto out;
    }

    const char *line_start = file_bytes;
    uint8_t *data_ptr = dst->data;

    while (*line_start != '\0') {
        const char *line_end = strchr(line_start, '\n');
        if (line_end == NULL) {
            line_end = line_start + strlen(line_start);
        }

        char domain[DNS_QNAME_MAX_LEN];
        size_t type_len;

        res = parse_query_line(
            line_start, line_end,
            &type_len, domain,
            sizeof(domain)
        );

        if (res) {
            dns_query_t query;
            query.domain = domain;
            query.qtype  = str_to_dns_qtype(line_start, type_len);
            query.qclass = DNS_QCLASS_IN;

            const ssize_t written = dns_build_query(data_ptr, buf_sz, query);
            if (written < 0) {
                res = LOAD_ERR_BADFORMAT;
                if (get_build_status(written) == BUILD_ERR_BUFSIZE)
                    res = LOAD_ERR_BUFSIZE;
                goto out;
            }

            qiter_list_register(dst->metadata, data_ptr, written);

            buf_sz   -= written;
            data_ptr += written;
        }

        if (*line_end == '\0')
            break;

        line_start = line_end + 1;
    }

    res = count;
out:
    free(file_bytes);
    return res;
}

void packet_array_destroy(packet_array_t *array)
{
    if (array == NULL)
        return;

    qiter_list_destroy(array->metadata);
    free(array->data);

    array->metadata = NULL;
    array->data = NULL;
}

static bool is_file_exists(const char *filename)
{
    assert(filename != NULL);
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

ssize_t open_file(FILE **dst, const char *filename)
{
    assert(dst != NULL);
    assert(filename != NULL);

    if (!is_file_exists(filename))
        return LOAD_ERR_NOFILE;

    FILE *f = fopen(filename, "r");
    if (f == NULL)
        return LOAD_ERR_OPENFILE;

    *dst = f;
    return LOAD_OK;
}

static size_t get_file_size(const char *filename)
{
    struct stat st;
    assert(filename != NULL);
    stat(filename, &st);
    return st.st_size;
}

ssize_t read_file_to_buffer(
    char **dst,
    const char *filename
)
{
    assert(dst != NULL);
    assert(filename != NULL);

    size_t file_sz = get_file_size(filename);

    *dst = malloc(file_sz + 1);
    if (*dst == NULL)
        return LOAD_ERR_ALLOC;

    FILE *f = NULL;
    ssize_t res = open_file(&f, filename);
    if (res < 0) {
        free(*dst);
        return res;
    }

    fread(*dst, 1, file_sz, f);
    (*dst)[file_sz] = '\0';

    fclose(f);
    return LOAD_OK;
}

// Estimates the total packet size of valid DNS queries in the buffer.
// Counts the total number of successfully parsed lines via the count pointer.
size_t estimate_valid_queries(const char *buf, size_t *count)
{
    const char *line_start = buf;
    size_t total_size = 0;
    size_t total_count = 0;

    while (*line_start != '\0') {
        const char *line_end = strchr(line_start, '\n');
        if (line_end == NULL) {
            line_end = line_start + strlen(line_start);
        }

        char domain[DNS_QNAME_MAX_LEN];
        size_t type_len;

        // directly use our single parser routine
        if (parse_query_line(line_start, line_end, &type_len, domain, sizeof(domain))) {
            total_size += dns_query_packet_size(domain);
            total_count++;
        }

        if (*line_end == '\0') break;

        // move to next line
        line_start = line_end + 1;
    }

    if (count != NULL) *count = total_count;
    return total_size;
}

// Parses a line bounded by [line_start, line_end).
// Extracts query type length and the clean domain string.
bool parse_query_line(
    const char *line_start,
    const char *line_end,
    size_t *out_type_len,
    char *out_domain,
    const size_t max_domain_len
)
{
    // skip leading spaces
    while (line_start < line_end && *line_start == ' ') {
        line_start++;
    }

    // find the separator space between TYPE and DOMAIN
    const char *space = line_start;
    while (space < line_end && *space != ' ') {
        space++;
    }

    // space no found, or TYPE is empty
    if (space == line_end || space == line_start) {
        return false;
    }

    *out_type_len = (size_t)(space - line_start);

    // skip spaces between TYPE and DOMAIN
    while (space < line_end && *space == ' ') {
        space++;
    }

    // find the end of the domain and strip trailing spaces, \r, \n
    const char *domain_end = line_end;
    while (domain_end > space) {
        char c = *(domain_end - 1);
        if (c == ' ' || c == '\r' || c == '\n') {
            domain_end--;
        } else {
            break;
        }
    }

    const size_t domain_len = (size_t)(domain_end - space);
    if (domain_len == 0 || domain_len >= max_domain_len) {
        // no domain or invalid domain length
        return false;
    }

    // extract the domain
    memcpy(out_domain, space, domain_len);
    out_domain[domain_len] = '\0';

    for (size_t i = 0; i < domain_len; i++) {
        if (out_domain[i] == ' ')
            // spaces inside the domain itself
            return false;
    }

    return true;
}

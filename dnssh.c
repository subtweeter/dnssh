
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <zlib.h>
#include <sodium.h>
#include <termios.h>
#include <pty.h>
#include <signal.h>
#include <grp.h>

#ifndef COMMIT_SHA
#define COMMIT_SHA "unknown"
#endif

#define DNSSH_VERSION "0.1"
#define MAX_PAYLOAD 280                     // fits comfortably under 512 B total packet
#define SESSION_ID_LEN 16
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define KEY_LEN crypto_secretbox_KEYBYTES
#define MAX_LABEL 63
#define HEARTBEAT_SEC 45
#define RETRY_BASE_MS 800
#define MAX_RESOLVERS 10
#define IO_CHUNK 64
#define MAX_INPUT_BUFFER 4096
#define MAX_PENDING_OUT 32768
#define DNSSH_PROMPT "\x1b[32mdnssh$ \x1b[0m"
#define CMD_RESEND_MAX_MS 5000
#define COMMAND_STALL_SEC 90
#define RESOLVER_SWITCH_BASE_SEC 12
#define RESOLVER_SWITCH_MAX_SEC 60
#define CONNECT_TIMEOUT_SEC 75
#define RESOLVER_SCAN_ATTEMPTS 2
#define RESOLVER_SCAN_TIMEOUT_FAST_MS 650
#define RESOLVER_SCAN_TIMEOUT_SLOW_MS 2200
#define RESOLVER_FANOUT_PARALLEL 3

static char g_domain[256];
static uint16_t g_server_port = 53;

// ====================== PROTOCOL HEADER ======================
// The header serves as the 24-byte Nonce for xchacha20poly1305.
typedef struct __attribute__((packed)) {
    uint8_t  session_id[SESSION_ID_LEN]; // 16 bytes
    uint32_t seq;                        // 4 bytes
    uint32_t ts;                         // 4 bytes
} dnssh_packet_hdr_t;

// Session Tracking for Replay Protection and Output Separation
typedef struct {
    uint8_t session_id[SESSION_ID_LEN];
    uint32_t last_seq;
    time_t last_active;
    uint8_t pending_out[MAX_PENDING_OUT];
    size_t pending_len;
    size_t pending_off;
    int active;
    int pty_fd;
    pid_t pid;
    int pty_closed;
} dnssh_session_t;

#define MAX_SESSIONS 32
static dnssh_session_t g_sessions[MAX_SESSIONS];

// ====================== SHARED HELPERS ======================
static uint8_t shared_key[KEY_LEN];   // pre-shared for v0.1 (load from file in prod)

// Split encoded string into DNS labels (<=63 chars) and build wire-format QNAME
static size_t build_qname(const char *encoded, uint8_t *qname) {
    size_t len = strlen(encoded);
    size_t pos = 0, qpos = 0;
    while (pos < len) {
        size_t chunk = len - pos > MAX_LABEL ? MAX_LABEL : len - pos;
        qname[qpos++] = (uint8_t)chunk;
        memcpy(&qname[qpos], &encoded[pos], chunk);
        qpos += chunk;
        pos += chunk;
    }
    // append domain
    const char *d = g_domain;
    while (*d) {
        const char *dot = strchr(d, '.');
        size_t l = dot ? (size_t)(dot - d) : strlen(d);
        qname[qpos++] = (uint8_t)l;
        memcpy(&qname[qpos], d, l);
        qpos += l;
        d += l + (dot ? 1 : 0);
    }
    qname[qpos++] = 0; // root
    return qpos;
}

static int parse_port_arg(const char *s, uint16_t *out_port) {
    char *end = NULL;
    long p;

    if (!s || !out_port) return -1;
    p = strtol(s, &end, 10);
    if (*s == '\0' || !end || *end != '\0' || p < 1 || p > 65535) return -1;

    *out_port = (uint16_t)p;
    return 0;
}

static int set_domain_arg(const char *domain) {
    size_t len;

    if (!domain || *domain == '\0') return -1;
    len = strlen(domain);
    while (len > 0 && domain[len - 1] == '.') len--;
    if (len == 0 || len >= sizeof(g_domain)) return -1;

    memcpy(g_domain, domain, len);
    g_domain[len] = '\0';
    return 0;
}

static int split_labels(const char *name, char labels[][64], int max_labels) {
    int count = 0;
    const char *p = name;

    if (!name || !labels || max_labels <= 0) return -1;

    while (*p && count < max_labels) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63) return -1;
        memcpy(labels[count], p, l);
        labels[count][l] = '\0';
        count++;
        if (!dot) break;
        p = dot + 1;
    }

    return count;
}

static int labels_equal_ci(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_key(const char *hex, uint8_t *out_key, size_t out_len) {
    size_t hex_len;

    if (!hex || !out_key) return -1;
    hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out_key[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int copy_or_default(char *dst, size_t dst_len, const char *src, const char *fallback);

static int lookup_user_in_passwd(const char *username,
                                 uid_t *out_uid,
                                 gid_t *out_gid,
                                 char *out_home,
                                 size_t out_home_len,
                                 char *out_shell,
                                 size_t out_shell_len) {
    FILE *f;
    char line[512];

    if (!username || !out_uid || !out_gid || !out_home || !out_shell) return -1;

    f = fopen("/etc/passwd", "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char *fields[7] = {0};
        char *nl;
        char *p = line;
        int idx = 0;

        nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        while (idx < 6) {
            char *colon = strchr(p, ':');
            if (!colon) break;
            *colon = '\0';
            fields[idx++] = p;
            p = colon + 1;
        }
        if (idx != 6) continue;
        fields[6] = p;

        if (strcmp(fields[0], username) != 0) continue;

        {
            char *end_uid = NULL;
            char *end_gid = NULL;
            long uid_l = strtol(fields[2], &end_uid, 10);
            long gid_l = strtol(fields[3], &end_gid, 10);
            if (!end_uid || *end_uid != '\0' || uid_l < 0) continue;
            if (!end_gid || *end_gid != '\0' || gid_l < 0) continue;

            *out_uid = (uid_t)uid_l;
            *out_gid = (gid_t)gid_l;
            if (copy_or_default(out_home, out_home_len, fields[5], "/") != 0) continue;
            if (copy_or_default(out_shell, out_shell_len, fields[6], "/bin/sh") != 0) continue;
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

static int copy_or_default(char *dst, size_t dst_len, const char *src, const char *fallback) {
    size_t n;
    const char *v = (src && src[0]) ? src : fallback;

    if (!dst || dst_len == 0 || !v) return -1;
    n = strlen(v);
    if (n >= dst_len) return -1;
    memcpy(dst, v, n + 1);
    return 0;
}

static int parse_id_arg(const char *s, unsigned long *out) {
    char *end = NULL;
    unsigned long v;

    if (!s || !*s || !out) return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0') return -1;
    *out = v;
    return 0;
}

static int parse_resolver_arg(const char *arg, struct sockaddr_in *out_addr) {
    char ipbuf[64];
    const char *port_part = NULL;
    uint16_t port = 53;
    const char *colon;

    if (!arg || !out_addr) return -1;

    memset(out_addr, 0, sizeof(*out_addr));
    out_addr->sin_family = AF_INET;

    colon = strchr(arg, ':');
    if (colon) {
        size_t ip_len = (size_t)(colon - arg);
        if (ip_len == 0 || ip_len >= sizeof(ipbuf)) return -1;
        memcpy(ipbuf, arg, ip_len);
        ipbuf[ip_len] = '\0';
        port_part = colon + 1;
        if (parse_port_arg(port_part, &port) != 0) return -1;
    } else {
        size_t ip_len = strlen(arg);
        if (ip_len == 0 || ip_len >= sizeof(ipbuf)) return -1;
        memcpy(ipbuf, arg, ip_len + 1);
    }

    if (inet_pton(AF_INET, ipbuf, &out_addr->sin_addr) != 1) return -1;
    out_addr->sin_port = htons(port);
    return 0;
}

typedef struct {
    struct sockaddr_in addr;
    long best_rtt_ms;
    int valid;
} resolver_scan_result_t;

static int resolver_addr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    if (!a || !b) return 0;
    return a->sin_family == b->sin_family &&
           a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static char *trim_line_inplace(char *s) {
    char *start;
    char *end;

    if (!s) return s;

    start = s;
    while (*start && isspace((unsigned char)*start)) start++;

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) end--;
    *end = '\0';

    return start;
}

static int add_resolver_unique(struct sockaddr_in **dst,
                               int *inout_count,
                               int *inout_cap,
                               const struct sockaddr_in *candidate) {
    struct sockaddr_in *grown;
    int new_cap;

    if (!dst || !inout_count || !inout_cap || !candidate) return -1;

    for (int i = 0; i < *inout_count; i++) {
        if (resolver_addr_equal(&(*dst)[i], candidate)) {
            return 0;
        }
    }

    if (*inout_count >= *inout_cap) {
        new_cap = (*inout_cap > 0) ? (*inout_cap * 2) : 16;
        grown = realloc(*dst, (size_t)new_cap * sizeof(**dst));
        if (!grown) return -1;
        *dst = grown;
        *inout_cap = new_cap;
    }

    (*dst)[*inout_count] = *candidate;
    (*inout_count)++;
    return 1;
}

static int load_resolvers_from_file(const char *path,
                                    struct sockaddr_in **dst,
                                    int *inout_count,
                                    int *inout_cap) {
    FILE *f;
    char line[256];
    int line_no = 0;

    if (!path || !*path || !dst || !inout_count || !inout_cap) return -1;

    f = fopen(path, "r");
    if (!f) {
        perror("[DNSSH] Failed to open resolver file");
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *entry;
        struct sockaddr_in parsed;

        line_no++;

        if (!strchr(line, '\n') && !feof(f)) {
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) {}
            fprintf(stderr, "[DNSSH] Resolver file line too long at %s:%d\n", path, line_no);
            fclose(f);
            return -1;
        }

        entry = trim_line_inplace(line);
        if (*entry == '\0' || *entry == '#' || *entry == ';') continue;

        if (parse_resolver_arg(entry, &parsed) != 0) {
            fprintf(stderr, "[DNSSH] Invalid resolver in %s:%d -> %s\n", path, line_no, entry);
            fclose(f);
            return -1;
        }

        if (add_resolver_unique(dst, inout_count, inout_cap, &parsed) < 0) {
            fprintf(stderr, "[DNSSH] Failed to grow resolver list while reading %s\n", path);
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

static long timeval_diff_ms(const struct timeval *start, const struct timeval *end) {
    long sec;
    long usec;

    if (!start || !end) return 0;
    sec = (long)(end->tv_sec - start->tv_sec);
    usec = (long)(end->tv_usec - start->tv_usec);
    return sec * 1000L + usec / 1000L;
}

static void format_resolver_addr(const struct sockaddr_in *addr, char *out, size_t out_len) {
    char ipbuf[INET_ADDRSTRLEN];

    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!addr) {
        snprintf(out, out_len, "<invalid>");
        return;
    }

    if (!inet_ntop(AF_INET, &addr->sin_addr, ipbuf, sizeof(ipbuf))) {
        snprintf(out, out_len, "<invalid>");
        return;
    }

    snprintf(out, out_len, "%s:%u", ipbuf, (unsigned)ntohs(addr->sin_port));
}

static size_t build_dns_txt_probe_query(const char *qname, uint16_t id, uint8_t *packet, size_t packet_cap) {
    const char *p;
    size_t off;
    uint16_t id_n;
    uint16_t flags;
    uint16_t qd;
    uint16_t zero;
    uint16_t qtype;
    uint16_t qclass;

    if (!qname || !*qname || !packet || packet_cap < 20) return 0;

    off = 0;
    id_n = htons(id);
    flags = htons(0x0100);
    qd = htons(1);
    zero = 0;

    memcpy(packet + off, &id_n, 2); off += 2;
    memcpy(packet + off, &flags, 2); off += 2;
    memcpy(packet + off, &qd, 2); off += 2;
    memcpy(packet + off, &zero, 2); off += 2;
    memcpy(packet + off, &zero, 2); off += 2;
    memcpy(packet + off, &zero, 2); off += 2;

    p = qname;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);

        if (label_len == 0 || label_len > 63) return 0;
        if (off + 1 + label_len + 5 > packet_cap) return 0;

        packet[off++] = (uint8_t)label_len;
        memcpy(packet + off, p, label_len);
        off += label_len;

        if (!dot) break;
        p = dot + 1;
    }

    if (off + 1 + 4 > packet_cap) return 0;
    packet[off++] = 0;

    qtype = htons(16);
    qclass = htons(1);
    memcpy(packet + off, &qtype, 2); off += 2;
    memcpy(packet + off, &qclass, 2); off += 2;

    return off;
}

static int resolver_scan_cmp(const void *lhs, const void *rhs) {
    const resolver_scan_result_t *a = (const resolver_scan_result_t *)lhs;
    const resolver_scan_result_t *b = (const resolver_scan_result_t *)rhs;
    uint32_t a_ip;
    uint32_t b_ip;
    uint16_t a_port;
    uint16_t b_port;

    if (a->best_rtt_ms < b->best_rtt_ms) return -1;
    if (a->best_rtt_ms > b->best_rtt_ms) return 1;

    a_ip = ntohl(a->addr.sin_addr.s_addr);
    b_ip = ntohl(b->addr.sin_addr.s_addr);
    if (a_ip < b_ip) return -1;
    if (a_ip > b_ip) return 1;

    a_port = ntohs(a->addr.sin_port);
    b_port = ntohs(b->addr.sin_port);
    if (a_port < b_port) return -1;
    if (a_port > b_port) return 1;
    return 0;
}

static int scan_and_sort_resolvers(const struct sockaddr_in *input,
                                   int input_count,
                                   struct sockaddr_in **out_sorted,
                                   int *out_count) {
    resolver_scan_result_t *results = NULL;
    uint16_t *tx_ids = NULL;
    struct timeval *sent_at = NULL;
    int *awaiting = NULL;
    resolver_scan_result_t *valid = NULL;
    struct sockaddr_in *sorted = NULL;
    int unresolved;
    int scan_sock = -1;
    int rc = -1;
    char probe_name[320];

    if (!input || !out_sorted || !out_count || input_count <= 0) return -1;
    *out_sorted = NULL;
    *out_count = 0;

    results = calloc((size_t)input_count, sizeof(*results));
    tx_ids = calloc((size_t)input_count, sizeof(*tx_ids));
    sent_at = calloc((size_t)input_count, sizeof(*sent_at));
    awaiting = calloc((size_t)input_count, sizeof(*awaiting));
    if (!results || !tx_ids || !sent_at || !awaiting) goto cleanup;

    for (int i = 0; i < input_count; i++) {
        results[i].addr = input[i];
        results[i].best_rtt_ms = 0;
        results[i].valid = 0;
    }

    if (snprintf(probe_name, sizeof(probe_name), "scan-%08x.%s", (unsigned)randombytes_random(), g_domain) >= (int)sizeof(probe_name)) {
        goto cleanup;
    }

    scan_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (scan_sock < 0) goto cleanup;
    fcntl(scan_sock, F_SETFL, O_NONBLOCK);

    unresolved = input_count;
    for (int attempt = 0; attempt < RESOLVER_SCAN_ATTEMPTS && unresolved > 0; attempt++) {
        long stage_timeout_ms = (attempt == 0) ? RESOLVER_SCAN_TIMEOUT_FAST_MS : RESOLVER_SCAN_TIMEOUT_SLOW_MS;
        struct timeval stage_start;
        int sent_any = 0;

        for (int i = 0; i < input_count; i++) {
            uint8_t query[512];
            size_t qlen;

            if (results[i].valid) continue;

            tx_ids[i] = (uint16_t)randombytes_random();
            qlen = build_dns_txt_probe_query(probe_name, tx_ids[i], query, sizeof(query));
            if (qlen == 0) continue;

            gettimeofday(&sent_at[i], NULL);
            awaiting[i] = 1;
            sent_any = 1;
            sendto(scan_sock, query, qlen, 0,
                   (const struct sockaddr *)&results[i].addr, sizeof(results[i].addr));
        }

        if (!sent_any) break;
        gettimeofday(&stage_start, NULL);

        while (unresolved > 0) {
            struct timeval now;
            long elapsed_ms;
            long remaining_ms;
            struct timeval tv;
            fd_set rfds;
            int sel;

            gettimeofday(&now, NULL);
            elapsed_ms = timeval_diff_ms(&stage_start, &now);
            remaining_ms = stage_timeout_ms - elapsed_ms;
            if (remaining_ms <= 0) break;

            tv.tv_sec = remaining_ms / 1000L;
            tv.tv_usec = (remaining_ms % 1000L) * 1000L;
            FD_ZERO(&rfds);
            FD_SET(scan_sock, &rfds);

            sel = select(scan_sock + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (sel == 0 || !FD_ISSET(scan_sock, &rfds)) continue;

            for (;;) {
                uint8_t resp[1024];
                struct sockaddr_in from;
                socklen_t from_len = sizeof(from);
                ssize_t rn = recvfrom(scan_sock, resp, sizeof(resp), 0,
                                      (struct sockaddr *)&from, &from_len);
                if (rn < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                if (rn < 12) continue;

                uint16_t resp_id;
                uint16_t resp_flags;
                memcpy(&resp_id, resp, 2);
                memcpy(&resp_flags, resp + 2, 2);
                resp_id = ntohs(resp_id);
                resp_flags = ntohs(resp_flags);
                if (!(resp_flags & 0x8000)) continue;

                for (int i = 0; i < input_count; i++) {
                    long rtt_ms;

                    if (results[i].valid || !awaiting[i]) continue;
                    if (!resolver_addr_equal(&from, &results[i].addr)) continue;
                    if (resp_id != tx_ids[i]) continue;

                    gettimeofday(&now, NULL);
                    rtt_ms = timeval_diff_ms(&sent_at[i], &now);
                    if (rtt_ms < 0) rtt_ms = 0;

                    results[i].valid = 1;
                    results[i].best_rtt_ms = rtt_ms;
                    awaiting[i] = 0;
                    unresolved--;
                    break;
                }
            }
        }

        for (int i = 0; i < input_count; i++) {
            awaiting[i] = 0;
        }
    }

    valid = malloc((size_t)input_count * sizeof(*valid));
    if (!valid) goto cleanup;

    {
        int valid_count = 0;

        for (int i = 0; i < input_count; i++) {
            if (!results[i].valid) continue;
            valid[valid_count++] = results[i];
        }

        if (valid_count <= 0) {
            rc = 0;
            goto cleanup;
        }

        qsort(valid, (size_t)valid_count, sizeof(valid[0]), resolver_scan_cmp);

        sorted = malloc((size_t)valid_count * sizeof(*sorted));
        if (!sorted) goto cleanup;

        for (int i = 0; i < valid_count; i++) {
            sorted[i] = valid[i].addr;
        }

        *out_sorted = sorted;
        *out_count = valid_count;
        sorted = NULL;
    }

    rc = 0;

cleanup:
    if (scan_sock >= 0) close(scan_sock);
    free(results);
    free(tx_ids);
    free(sent_at);
    free(awaiting);
    free(valid);
    free(sorted);
    return rc;
}

static int resolver_fanout_count(int num_resolvers) {
    if (num_resolvers <= 0) return 0;
    if (num_resolvers < RESOLVER_FANOUT_PARALLEL) return num_resolvers;
    return RESOLVER_FANOUT_PARALLEL;
}

static void send_query_to_fanout(int sock,
                                 const uint8_t *query,
                                 size_t qlen,
                                 const struct sockaddr_in *resolvers,
                                 int num_resolvers,
                                 int fanout_base,
                                 int fanout_count) {
    int count;

    if (sock < 0 || !query || qlen == 0 || !resolvers || num_resolvers <= 0 || fanout_count <= 0) return;

    count = fanout_count > num_resolvers ? num_resolvers : fanout_count;
    for (int i = 0; i < count; i++) {
        int idx = (fanout_base + i) % num_resolvers;
        sendto(sock, query, qlen, 0, (const struct sockaddr *)&resolvers[idx], sizeof(resolvers[idx]));
    }
}

static int send_query_window_rr(int sock,
                                const uint8_t *query,
                                size_t qlen,
                                const struct sockaddr_in *resolvers,
                                int num_resolvers,
                                int fanout_base,
                                int fanout_count,
                                int *rr_cursor) {
    int count;
    int local_cursor;
    int idx;

    if (sock < 0 || !query || qlen == 0 || !resolvers || num_resolvers <= 0 || fanout_count <= 0) return -1;

    count = fanout_count > num_resolvers ? num_resolvers : fanout_count;
    local_cursor = (rr_cursor && *rr_cursor >= 0) ? *rr_cursor : 0;
    idx = (fanout_base + (local_cursor % count)) % num_resolvers;

    sendto(sock, query, qlen, 0, (const struct sockaddr *)&resolvers[idx], sizeof(resolvers[idx]));

    if (rr_cursor) {
        *rr_cursor = (local_cursor + 1) % count;
    }

    return idx;
}

    static void hex_encode_bytes(const uint8_t *in, size_t in_len, char *out) {
        static const char hx[] = "0123456789abcdef";
        for (size_t i = 0; i < in_len; i++) {
            out[i * 2] = hx[(in[i] >> 4) & 0x0f];
            out[i * 2 + 1] = hx[in[i] & 0x0f];
        }
        out[in_len * 2] = '\0';
    }

    static size_t hex_decode_bytes(const char *in, uint8_t *out, size_t out_cap) {
        size_t in_len = strlen(in);
        size_t out_len;

        if (in_len % 2 != 0) return 0;
        out_len = in_len / 2;
        if (out_len > out_cap) return 0;

        for (size_t i = 0; i < out_len; i++) {
            int hi = hex_nibble(in[i * 2]);
            int lo = hex_nibble(in[i * 2 + 1]);
            if (hi < 0 || lo < 0) return 0;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return out_len;
    }

// ====================== DNS PACKET BUILD / PARSE ======================
static uint16_t dns_id_counter = 0;

static int encode_tunnel_payload_b32(const uint8_t *session_id, const uint8_t *payload, size_t pay_len, char *out_b32, size_t out_b32_cap) {
    dnssh_packet_hdr_t hdr;
    uLongf comp_len;
    uint8_t *comp;
    uint8_t *cipher;
    uint8_t *tunnel;
    size_t tunnel_len;
    size_t need_hex;

    if (!payload || !out_b32 || out_b32_cap == 0 || !session_id) return -1;

    memcpy(hdr.session_id, session_id, SESSION_ID_LEN);
    hdr.seq = dns_id_counter++;
    hdr.ts = (uint32_t)time(NULL);

    comp_len = compressBound(pay_len);
    comp = malloc(comp_len);
    if (!comp) return -1;
    if (compress(comp, &comp_len, payload, pay_len) != Z_OK) {
        free(comp);
        return -1;
    }

    cipher = malloc(comp_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (!cipher) {
        free(comp);
        return -1;
    }
    
    unsigned long long clen;
    // Header is the 24-byte nonce.
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher, &clen,
        comp, comp_len,
        (unsigned char*)&hdr, sizeof(hdr), // AAD protects the header exactly
        NULL,
        (const unsigned char *)&hdr, // Nonce is exactly the 24 byte header
        shared_key
    );
    free(comp);

    tunnel_len = sizeof(hdr) + clen;
    tunnel = malloc(tunnel_len);
    if (!tunnel) {
        free(cipher);
        return -1;
    }
    memcpy(tunnel, &hdr, sizeof(hdr));
    memcpy(tunnel + sizeof(hdr), cipher, clen);
    free(cipher);


        need_hex = tunnel_len * 2 + 1;
    if (need_hex > out_b32_cap) {
        free(tunnel);
        return -1;
    }

        hex_encode_bytes(tunnel, tunnel_len, out_b32);
    free(tunnel);
    return 0;
}

static size_t build_dns_query(const uint8_t *session_id, const uint8_t *payload, size_t pay_len, uint8_t *packet, uint16_t *out_id) {
    char b32[1024];
    if (encode_tunnel_payload_b32(session_id, payload, pay_len, b32, sizeof(b32)) != 0) return 0;

    size_t qname_len = build_qname(b32, packet + 12);
    uint16_t id = dns_id_counter++;
    *out_id = id;

    // DNS header
    uint8_t *p = packet;
    uint16_t nid = htons(id);
    memcpy(p, &nid, 2); p += 2;          // ID
    uint16_t flags = htons(0x0100); memcpy(p, &flags, 2); p += 2;  // standard query
    uint16_t qd = htons(1); memcpy(p, &qd, 2); p += 2;
    uint16_t zero = 0; memcpy(p, &zero, 2); p += 2; // AN/NS/AR
    memcpy(p, &zero, 2); p += 2;
    memcpy(p, &zero, 2); p += 2;

    // QNAME already written at offset 12
    p = packet + 12 + qname_len;

    uint16_t qtype = htons(16); memcpy(p, &qtype, 2); p += 2;  // TXT
    uint16_t qclass = htons(1); memcpy(p, &qclass, 2); p += 2;

    return (size_t)(p - packet);
}

static size_t build_dns_txt_response(const uint8_t *session_id, const uint8_t *query, size_t qlen,
                                     const uint8_t *payload, size_t pay_len,
                                     uint8_t *response, size_t response_cap) {
    size_t off = 12;
    size_t question_len;
    size_t p;
    char b32[1024];
    size_t b32_len;

    if (!query || !response || qlen < 12 || response_cap < 32 || !session_id) return 0;
    if (encode_tunnel_payload_b32(session_id, payload, pay_len, b32, sizeof(b32)) != 0) return 0;
    b32_len = strlen(b32);

    // Keep parser compatibility: support multi-string TXT in RDATA to break 255 byte limit.
    if (b32_len == 0) return 0;

    while (off < qlen && query[off] != 0) {
        uint8_t l = query[off];
        if (l == 0 || off + 1 + l > qlen) return 0;
        off += 1 + l;
    }
    if (off >= qlen) return 0;
    off++; // zero label
    if (off + 4 > qlen) return 0; // qtype + qclass

    question_len = off + 4 - 12;

    // Header
    uint16_t id;
    memcpy(&id, query, 2); // reuse query ID (network byte order)
    memcpy(response, &id, 2);
    {
        uint16_t flags = htons(0x8180);
        uint16_t qd = htons(1);
        uint16_t an = htons(1);
        uint16_t zero = 0;
        memcpy(response + 2, &flags, 2);
        memcpy(response + 4, &qd, 2);
        memcpy(response + 6, &an, 2);
        memcpy(response + 8, &zero, 2);
        memcpy(response + 10, &zero, 2);
    }

    p = 12;
    if (p + question_len > response_cap) return 0;
    memcpy(response + p, query + 12, question_len);
    p += question_len;

    uint16_t num_chunks = (uint16_t)((b32_len + 254) / 255);
    uint16_t rdlen = (uint16_t)(b32_len + num_chunks);

    // Answer NAME = pointer to question name at offset 12 (0xC00C)
    if (p + 2 + 2 + 2 + 4 + 2 + rdlen > response_cap) return 0;
    response[p++] = 0xC0;
    response[p++] = 0x0C;
    {
        uint16_t type = htons(16);   // TXT
        uint16_t qclass = htons(1);  // IN
        uint32_t ttl = htonl(0);
        uint16_t rdlen_n = htons(rdlen);
        memcpy(response + p, &type, 2); p += 2;
        memcpy(response + p, &qclass, 2); p += 2;
        memcpy(response + p, &ttl, 4); p += 4;
        memcpy(response + p, &rdlen_n, 2); p += 2;
    }
    
    size_t remain = b32_len;
    size_t off_b = 0;
    while(remain > 0) {
        size_t chunk = remain > 255 ? 255 : remain;
        response[p++] = (uint8_t)chunk;
        memcpy(response + p, b32 + off_b, chunk);
        p += chunk;
        off_b += chunk;
        remain -= chunk;
    }

    return p;
}

static int parse_dns_response(const uint8_t *packet, size_t len, uint8_t *out_payload, size_t out_cap, size_t *out_len) {
    if (len < 12) return -1;
    uint16_t id, flags, ancount;
    memcpy(&id, packet, 2);
    memcpy(&flags, packet + 2, 2);
    memcpy(&ancount, packet + 6, 2);
    flags = ntohs(flags);
    ancount = ntohs(ancount);
    if (!(flags & 0x8000)) return -1; // not response

    // skip QNAME + question
    size_t off = 12;
    while (off < len && packet[off] != 0) off += packet[off] + 1;
    off += 5; // null + type + class

    for (uint16_t i = 0; i < ancount; i++) {
        // skip name
        while (off < len && packet[off] != 0) {
            if (packet[off] & 0xc0) { off += 2; break; }
            off += packet[off] + 1;
        }
        if (off + 10 >= len) return -1;
        off += 2; // type
        off += 2; // class
        off += 4; // TTL
        uint16_t rdlen; memcpy(&rdlen, packet + off, 2); rdlen = ntohs(rdlen);
        off += 2;
        if (off + rdlen > len) return -1;

        if (rdlen > 0) {
            size_t txt_len = 0;
            char txtbuf[2048];
            size_t rdoff = off;
            while (rdoff < off + rdlen) {
                size_t chunk = packet[rdoff++];
                if (rdoff + chunk > off + rdlen) return -1;
                if (txt_len + chunk >= sizeof(txtbuf)) return -1;
                memcpy(txtbuf + txt_len, packet + rdoff, chunk);
                txt_len += chunk;
                rdoff += chunk;
            }
            txtbuf[txt_len] = '\0';

            uint8_t tunnel[2048];
                size_t tunnel_len = hex_decode_bytes(txtbuf, tunnel, sizeof(tunnel));

            if (tunnel_len < sizeof(dnssh_packet_hdr_t) + crypto_aead_xchacha20poly1305_ietf_ABYTES) return -1;

            dnssh_packet_hdr_t *hdr = (dnssh_packet_hdr_t *)tunnel;
            uint8_t *cipher = tunnel + sizeof(dnssh_packet_hdr_t);
            size_t cipher_len = tunnel_len - sizeof(dnssh_packet_hdr_t);

            // decrypt
            uint8_t *plain = malloc(cipher_len);
            if (!plain) return -1;
            unsigned long long plen;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plain, &plen,
                    NULL,
                    cipher, cipher_len,
                    (unsigned char *)hdr, sizeof(dnssh_packet_hdr_t), // AAD
                    (unsigned char *)hdr, // Nonce
                    shared_key) != 0) {
                free(plain); return -1;
            }

            // decompress
            uLongf outsize = MAX_PAYLOAD * 4;
            uint8_t *decomp = malloc(outsize);
            if (uncompress(decomp, &outsize, plain, plen) == Z_OK) {
                if (outsize > out_cap) {
                    free(plain); free(decomp);
                    return -1;
                }
                memcpy(out_payload, decomp, outsize);
                *out_len = outsize;
                free(plain); free(decomp);
                return 0;
            }
            free(plain); free(decomp);
        }
        off += rdlen;
    }
    return -1;
}

// ====================== CLIENT ======================
int main_client(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <domain> <key_hex_64> <resolver_or_@file> [resolver_or_@file] ...\n", argv[0]);
        return 1;
    }

    if (set_domain_arg(argv[1]) != 0) {
        fprintf(stderr, "Invalid domain: %s\n", argv[1]);
        return 1;
    }

    if (parse_hex_key(argv[2], shared_key, KEY_LEN) != 0) {
        fprintf(stderr, "Invalid key: expected %u hex chars\n", (unsigned)(KEY_LEN * 2));
        return 1;
    }

    struct sockaddr_in *input_resolvers = NULL;
    struct sockaddr_in *resolvers = NULL;
    int arg_resolvers = argc - 3;
    int input_cap = 0;
    int num_res = 0;

    for (int i = 0; i < arg_resolvers; i++) {
        const char *arg = argv[i + 3];
        const char *file_path = arg;
        int should_load_file = 0;

        if (arg[0] == '@') {
            if (arg[1] == '\0') {
                fprintf(stderr, "Invalid resolver file argument: @\n");
                free(input_resolvers);
                return 1;
            }
            should_load_file = 1;
            file_path = arg + 1;
        }

        if (should_load_file) {
            int before = num_res;
            if (load_resolvers_from_file(file_path, &input_resolvers, &num_res, &input_cap) != 0) {
                free(input_resolvers);
                return 1;
            }
            printf("[DNSSH] Loaded %d resolver(s) from file: %s\n", num_res - before, file_path);
            continue;
        }

        struct sockaddr_in parsed;
        if (parse_resolver_arg(arg, &parsed) != 0) {
            fprintf(stderr, "Invalid resolver (expected ip, ip:port, or @file): %s\n", arg);
            free(input_resolvers);
            return 1;
        }
        if (add_resolver_unique(&input_resolvers, &num_res, &input_cap, &parsed) < 0) {
            fprintf(stderr, "Failed to grow resolver list (out of memory).\n");
            free(input_resolvers);
            return 1;
        }
    }

    if (num_res <= 0) {
        fprintf(stderr, "No usable resolver addresses provided.\n");
        free(input_resolvers);
        return 1;
    }

    printf("[DNSSH] Scanning %d resolver(s) for reachability...\n", num_res);
    {
        struct sockaddr_in *validated = NULL;
        int validated_count = 0;

        if (scan_and_sort_resolvers(input_resolvers, num_res, &validated, &validated_count) != 0) {
            fprintf(stderr, "[DNSSH] Resolver scan failed due to internal error.\n");
            free(input_resolvers);
            return 1;
        }

        free(input_resolvers);
        input_resolvers = NULL;

        if (validated_count <= 0) {
            fprintf(stderr, "[DNSSH] No validated resolvers responded. Aborting connection.\n");
            free(validated);
            return 1;
        }

        resolvers = validated;
        num_res = validated_count;
        printf("[DNSSH] Using %d validated resolver(s), sorted by RTT.\n", num_res);
        for (int i = 0; i < num_res; i++) {
            char resolver_text[64];
            format_resolver_addr(&resolvers[i], resolver_text, sizeof(resolver_text));
            printf("[DNSSH]   %d) %s\n", i + 1, resolver_text);
        }
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    uint8_t session_id[SESSION_ID_LEN];
    randombytes_buf(session_id, SESSION_ID_LEN);

    printf("[DNSSH] Client started (Build: %s) - Session ID: ", COMMIT_SHA);
    for (int i = 0; i < SESSION_ID_LEN; i++) printf("%02x", session_id[i]);
    printf("\nDomain: %s\n", g_domain);

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    time_t last_heartbeat = 0;
    int fanout_count = resolver_fanout_count(num_res);
    int fanout_base = 0;
    int pull_rr_cursor = 0;
    int waiting_for_command_output = 0;
    int saw_output_for_command = 0;
    int empty_polls_after_output = 0;
    long current_poll_interval_us = 250000L;
    struct timeval last_pull = {0, 0};
    struct timeval last_command_send = {0, 0};
    uint8_t last_command_query[512];
    size_t last_command_query_len = 0;
    uint16_t last_command_dns_id = 0;
    int command_inflight = 0;
    long current_resend_interval_us = RETRY_BASE_MS * 1000L;
    long current_switch_after_sec = RESOLVER_SWITCH_BASE_SEC;
    uint8_t pending_input[MAX_INPUT_BUFFER];
    size_t pending_input_len = 0;
    int should_exit = 0;
    uint8_t buf[4096];

    printf("[DNSSH] Fanout mode: command packets sent to %d resolver(s) in parallel.\n", fanout_count);

    printf("[DNSSH] Requesting connection (this may take a few seconds)...\n");

    // Fetch initial PTY prompt and sync PTY size if possible
    {
        char init_cmd[128];
        size_t init_len = 0;
        struct winsize wz;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &wz) == 0 && wz.ws_row > 0 && wz.ws_col > 0) {
            init_len = snprintf(init_cmd, sizeof(init_cmd), "stty rows %d cols %d\n", wz.ws_row, wz.ws_col);
        } else {
            init_cmd[0] = 0;
        }

        uint16_t id;
        uint8_t query[512];
        size_t qlen = build_dns_query(session_id, (uint8_t *)init_cmd, init_len, query, &id);
        if (qlen > 0) {
            send_query_to_fanout(sock, query, qlen, resolvers, num_res, fanout_base, fanout_count);
            waiting_for_command_output = 1;
            saw_output_for_command = 0;
            empty_polls_after_output = 0;
            gettimeofday(&last_pull, NULL);
            if (init_len > 0 && qlen <= sizeof(last_command_query)) {
                memcpy(last_command_query, query, qlen);
                last_command_query_len = qlen;
                last_command_dns_id = id;
                command_inflight = 1;
                gettimeofday(&last_command_send, NULL);
                current_resend_interval_us = RETRY_BASE_MS * 1000L;
            } else {
                command_inflight = 0;
                last_command_query_len = 0;
            }
        }
    }

    struct termios old_tio, new_tio;
    int has_tty = (tcgetattr(STDIN_FILENO, &old_tio) == 0);
    
    int is_connected = 0;
    struct timeval last_response;
    gettimeofday(&last_response, NULL);
    struct timeval last_resolver_switch = last_response;
    
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock, &fds);
        int max_fd = sock > STDIN_FILENO ? sock : STDIN_FILENO;
        
        struct timeval tv = {0, 100000}; // 100ms idle timeout

        if (select(max_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            // user input -> send over DNS tunnel
            if (is_connected && FD_ISSET(STDIN_FILENO, &fds)) {
                ssize_t n = read(STDIN_FILENO, buf, IO_CHUNK);
                if (n > 0) {
                    size_t append_off = 0;
                    for (ssize_t i = 0; i < n; i++) {
                        uint8_t ch = buf[i];
                        if (ch == 0x04) { // Ctrl+D
                            should_exit = 1;
                            break;
                        }
                        append_off = (size_t)(i + 1);
                    }

                    if (should_exit) {
                        const char *logout_msg = "\r\nlogout\r\n";
                        ssize_t lw = write(STDOUT_FILENO, logout_msg, strlen(logout_msg));
                        (void)lw;
                        break;
                    }

                    if (append_off > 0) {
                        size_t room = sizeof(pending_input) - pending_input_len;
                        size_t copy_len = append_off > room ? room : append_off;
                        if (copy_len > 0) {
                            memcpy(pending_input + pending_input_len, buf, copy_len);
                            pending_input_len += copy_len;
                        }
                    }

                    if (!command_inflight && pending_input_len > 0) {
                        size_t send_len = pending_input_len > IO_CHUNK ? IO_CHUNK : pending_input_len;
                        uint16_t id;
                        uint8_t query[512];
                        size_t qlen = build_dns_query(session_id, pending_input, send_len, query, &id);
                        if (qlen > 0) {
                            send_query_to_fanout(sock, query, qlen, resolvers, num_res, fanout_base, fanout_count);
                            if (qlen <= sizeof(last_command_query)) {
                                memcpy(last_command_query, query, qlen);
                                last_command_query_len = qlen;
                                last_command_dns_id = id;
                                command_inflight = 1;
                                gettimeofday(&last_command_send, NULL);
                                current_resend_interval_us = RETRY_BASE_MS * 1000L;
                            }
                            if (pending_input_len > send_len) {
                                memmove(pending_input, pending_input + send_len, pending_input_len - send_len);
                            }
                            pending_input_len -= send_len;

                            waiting_for_command_output = 1;
                            saw_output_for_command = 0;
                            empty_polls_after_output = 0;
                            current_poll_interval_us = 250000L; // Start at 250ms when sending commands
                            gettimeofday(&last_pull, NULL);
                        }
                    }
                }
            }
        }

        if (should_exit) break;

        // receive DNS response
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t r = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        if (r > 0) {
            uint8_t payload[MAX_PAYLOAD * 4];
            size_t plen = 0;
            if (parse_dns_response(buf, r, payload, sizeof(payload), &plen) == 0) {
                uint16_t resp_id = 0;
                if ((size_t)r >= 2) {
                    memcpy(&resp_id, buf, 2);
                    resp_id = ntohs(resp_id);
                }
                gettimeofday(&last_response, NULL);
                last_resolver_switch = last_response;
                current_switch_after_sec = RESOLVER_SWITCH_BASE_SEC;
                current_resend_interval_us = RETRY_BASE_MS * 1000L;
                if (command_inflight && resp_id == last_command_dns_id) {
                    command_inflight = 0;
                    last_command_query_len = 0;
                }
                if (plen == 4 && memcmp(payload, "\xff\xff\xff\xff", 4) == 0) {
                    const char *msg = "\r\n[DNSSH] Remote session closed.\r\n";
                    ssize_t mw = write(STDOUT_FILENO, msg, strlen(msg));
                    (void)mw;
                    should_exit = 1;
                    continue;
                }

                if (!is_connected) {
                    is_connected = 1;
                    if (has_tty) {
                        new_tio = old_tio;
                        cfmakeraw(&new_tio);
                        tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
                    }
                    const char *conn_msg = 
                        "\r\n\x1b[33m"
                        "   \\|\\||\r\n"
                        "  -' ||||/\r\n"
                        " /7   |||||/\r\n"
                        "/    |||||||/`-.____________\r\n"
                        "\\-' |||||||||               `-._\r\n"
                        " -|||||||||||               |` -`.\r\n"
                        "   ||||||               \\   |   `\\\\\r\n"
                        "    |||||\\  \\______...---\\_  \\    \\\\\r\n"
                        "       |  \\  \\           | \\  |    ``-.__--.\r\n"
                        "       |  |\\  \\         / / | |       ``---'\r\n"
                        "     _/  /_/  /      __/ / _| |\r\n"
                        "    (,__/(,__/      (,__/ (,__/\x1b[0m\r\n\r\n"
                        "\x1b[32m  [DNSSH] Connected successfully! Type 'exit' to logout.\x1b[0m\r\n";
                    ssize_t cw = write(STDOUT_FILENO, conn_msg, strlen(conn_msg));
                    (void)cw;
                    
                    char build_msg[128];
                    snprintf(build_msg, sizeof(build_msg), "\x1b[34m  [DNSSH] Build: %s\x1b[0m\r\n\r\n", COMMIT_SHA);
                    cw = write(STDOUT_FILENO, build_msg, strlen(build_msg));
                    (void)cw;

                }

                ssize_t w = write(STDOUT_FILENO, payload, plen);
                (void)w;

                // Output received -> dynamically adapt poll interval
                if (plen > 0) {
                    saw_output_for_command = 1;
                    empty_polls_after_output = 0;
                    current_poll_interval_us = 100000L; // drop interval down to 100ms for fast reading

                    uint8_t dummy[1] = {0};
                    uint16_t id;
                    uint8_t query[512];
                    size_t qlen = build_dns_query(session_id, dummy, 0, query, &id);
                    if (qlen > 0) {
                        int sent_idx = send_query_window_rr(sock, query, qlen,
                                                            resolvers, num_res,
                                                            fanout_base, fanout_count,
                                                            &pull_rr_cursor);
                        (void)sent_idx;
                        gettimeofday(&last_pull, NULL);
                    }
                } else if (waiting_for_command_output) {
                    if (saw_output_for_command) {
                        empty_polls_after_output++;
                        
                        // Dynamically increase poll interval up to ~2 seconds if idle
                        current_poll_interval_us = current_poll_interval_us * 2;
                        if (current_poll_interval_us > 2000000L) current_poll_interval_us = 2000000L;

                        if (empty_polls_after_output >= 20) { // Timeout after ~15-20 seconds of no output
                            waiting_for_command_output = 0;
                            saw_output_for_command = 0;
                            empty_polls_after_output = 0;
                            command_inflight = 0;
                            last_command_query_len = 0;
                        }
                    }
                }
            }
        }

        // If the command is still pending and no output has arrived yet, keep polling.
        if (waiting_for_command_output) {
            struct timeval now;
            gettimeofday(&now, NULL);
            long elapsed_us = (long)((now.tv_sec - last_pull.tv_sec) * 1000000L +
                                     (now.tv_usec - last_pull.tv_usec));
            if (!command_inflight && elapsed_us >= current_poll_interval_us) {
                uint8_t dummy[1] = {0};
                uint16_t id;
                uint8_t query[512];
                size_t qlen = build_dns_query(session_id, dummy, 0, query, &id);
                if (qlen > 0) {
                    int sent_idx = send_query_window_rr(sock, query, qlen,
                                                        resolvers, num_res,
                                                        fanout_base, fanout_count,
                                                        &pull_rr_cursor);
                    (void)sent_idx;
                    last_pull = now;
                }
            }

            // Retransmit the latest non-empty command packet if no response arrives.
            if (command_inflight && last_command_query_len > 0) {
                long resend_elapsed_us = (long)((now.tv_sec - last_command_send.tv_sec) * 1000000L +
                                                (now.tv_usec - last_command_send.tv_usec));
                if (resend_elapsed_us >= current_resend_interval_us) {
                    send_query_to_fanout(sock,
                                         last_command_query,
                                         last_command_query_len,
                                         resolvers,
                                         num_res,
                                         fanout_base,
                                         fanout_count);
                    last_command_send = now;
                    current_resend_interval_us *= 2;
                    if (current_resend_interval_us > (long)CMD_RESEND_MAX_MS * 1000L) {
                        current_resend_interval_us = (long)CMD_RESEND_MAX_MS * 1000L;
                    }
                }
            }

            if ((now.tv_sec - last_response.tv_sec) >= COMMAND_STALL_SEC) {
                waiting_for_command_output = 0;
                saw_output_for_command = 0;
                empty_polls_after_output = 0;
                command_inflight = 0;
                last_command_query_len = 0;
                current_poll_interval_us = 250000L;
                current_resend_interval_us = RETRY_BASE_MS * 1000L;
            }
        }

        if (is_connected && !command_inflight && pending_input_len > 0) {
            size_t send_len = pending_input_len > IO_CHUNK ? IO_CHUNK : pending_input_len;
            uint16_t id;
            uint8_t query[512];
            size_t qlen = build_dns_query(session_id, pending_input, send_len, query, &id);
            if (qlen > 0) {
                send_query_to_fanout(sock, query, qlen, resolvers, num_res, fanout_base, fanout_count);
                if (qlen <= sizeof(last_command_query)) {
                    memcpy(last_command_query, query, qlen);
                    last_command_query_len = qlen;
                    last_command_dns_id = id;
                    command_inflight = 1;
                    gettimeofday(&last_command_send, NULL);
                    current_resend_interval_us = RETRY_BASE_MS * 1000L;
                }
                if (pending_input_len > send_len) {
                    memmove(pending_input, pending_input + send_len, pending_input_len - send_len);
                }
                pending_input_len -= send_len;

                waiting_for_command_output = 1;
                saw_output_for_command = 0;
                empty_polls_after_output = 0;
                current_poll_interval_us = 250000L;
                gettimeofday(&last_pull, NULL);
            }
        }

        // heartbeat
        if (!command_inflight && time(NULL) - last_heartbeat > HEARTBEAT_SEC) {
            uint8_t dummy[1] = {0};
            uint16_t id;
            uint8_t query[512];
            size_t qlen = build_dns_query(session_id, dummy, 0, query, &id);  // empty payload = heartbeat
            if (qlen > 0) {
                int sent_idx = send_query_window_rr(sock, query, qlen,
                                                    resolvers, num_res,
                                                    fanout_base, fanout_count,
                                                    &pull_rr_cursor);
                (void)sent_idx;
            }
            last_heartbeat = time(NULL);
        }

        // Before first connect, shift the fanout window if a resolver group stalls.
        if (!is_connected) {
            struct timeval now;
            long elapsed_sec;
            long elapsed_since_switch;
            gettimeofday(&now, NULL);
            elapsed_sec = (long)(now.tv_sec - last_response.tv_sec);
            elapsed_since_switch = (long)(now.tv_sec - last_resolver_switch.tv_sec);

            if (!is_connected && elapsed_sec >= CONNECT_TIMEOUT_SEC) {
                printf("\r\n[DNSSH] Timed out waiting for server. Aborting connection.\r\n");
                break;
            }

            if (num_res > fanout_count && elapsed_sec >= current_switch_after_sec &&
                elapsed_since_switch >= current_switch_after_sec) {
                fanout_base = (fanout_base + fanout_count) % num_res;
                pull_rr_cursor = 0;
                last_resolver_switch = now;
                {
                    char resolver_text[64];
                    format_resolver_addr(&resolvers[fanout_base], resolver_text, sizeof(resolver_text));
                    printf("[DNSSH] Shifted fanout window -> %s (+%d peers)\r\n", resolver_text, fanout_count - 1);
                }
                current_switch_after_sec *= 2;
                if (current_switch_after_sec > RESOLVER_SWITCH_MAX_SEC) {
                    current_switch_after_sec = RESOLVER_SWITCH_MAX_SEC;
                }
            }
        }
    }

    if (has_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    }

    free(resolvers);

    return 0;
}

// ====================== SERVER ======================
static int udp_sock;

static void handle_dns_query(uint8_t *packet, size_t len, struct sockaddr_in *client) {
    // extract QNAME labels (skip header)
    size_t off = 12;
    char qlabels[128][64];
    int qlabel_count = 0;
    char dlabels[64][64];
    int dlabel_count;
    char encoded[1024] = {0};
    size_t epos = 0;

    while (off < len && packet[off] != 0 && qlabel_count < 128) {
        uint8_t l = packet[off++];
        if (l == 0 || l > 63 || off + l > len) goto reject;
        memcpy(qlabels[qlabel_count], packet + off, l);
        qlabels[qlabel_count][l] = '\0';
        qlabel_count++;
        off += l;
    }

    dlabel_count = split_labels(g_domain, dlabels, 64);
    if (dlabel_count <= 0 || qlabel_count <= 0) goto reject;

    // Strip the configured domain suffix so only payload labels remain.
    int payload_labels = qlabel_count;
    if (qlabel_count >= dlabel_count) {
        int is_suffix = 1;
        for (int i = 0; i < dlabel_count; i++) {
            if (!labels_equal_ci(qlabels[qlabel_count - dlabel_count + i], dlabels[i])) {
                is_suffix = 0;
                break;
            }
        }
        if (is_suffix) payload_labels = qlabel_count - dlabel_count;
    }

    for (int i = 0; i < payload_labels; i++) {
        size_t l = strlen(qlabels[i]);
        if (epos + l >= sizeof(encoded)) goto reject;
        memcpy(encoded + epos, qlabels[i], l);
        epos += l;
    }
    encoded[epos] = 0;

    uint8_t tunnel[2048];
        size_t tunnel_len = hex_decode_bytes(encoded, tunnel, sizeof(tunnel));
    if (tunnel_len < sizeof(dnssh_packet_hdr_t) + crypto_aead_xchacha20poly1305_ietf_ABYTES) goto reject;

    dnssh_packet_hdr_t *hdr = (dnssh_packet_hdr_t *)tunnel;
    uint8_t *cipher = tunnel + sizeof(dnssh_packet_hdr_t);
    size_t cipher_len = tunnel_len - sizeof(dnssh_packet_hdr_t);

    uint8_t *plain = malloc(cipher_len);
    if (!plain) goto reject;
    unsigned long long plen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, &plen,
            NULL,
            cipher, cipher_len,
            (unsigned char *)hdr, sizeof(dnssh_packet_hdr_t),
            (unsigned char *)hdr,
            shared_key) != 0) {
        free(plain); goto reject;
    }

    uLongf decomp_len = MAX_PAYLOAD * 4;
    uint8_t *decomp = malloc(decomp_len);
    if (uncompress(decomp, &decomp_len, plain, plen) != Z_OK) {
        free(plain); free(decomp); goto reject;
    }

    // --- Session / Replay Tracking ---
    int s_idx = -1;
    int is_replay = 0;
    time_t now = time(NULL);
    
    // Find existing session
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active && memcmp(g_sessions[i].session_id, hdr->session_id, SESSION_ID_LEN) == 0) {
            s_idx = i;
            break;
        }
    }
    
    if (s_idx >= 0) {
        // Replay check
        if (decomp_len > 0) {
            if (hdr->seq <= g_sessions[s_idx].last_seq) {
                // Do not execute duplicate command payloads, but still reply below.
                is_replay = 1;
            } else {
                g_sessions[s_idx].last_seq = hdr->seq;
            }
        }
        g_sessions[s_idx].last_active = now;
    } else {
        // Allocate new session
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (!g_sessions[i].active || (now - g_sessions[i].last_active > 300)) {
                s_idx = i;
                break;
            }
        }
        if (s_idx < 0) { // Full
            free(plain); free(decomp); return;
        }
        
        if (g_sessions[s_idx].active && g_sessions[s_idx].pty_fd >= 0) {
            close(g_sessions[s_idx].pty_fd);
            if (g_sessions[s_idx].pid > 0) kill(g_sessions[s_idx].pid, SIGKILL);
        }

        g_sessions[s_idx].active = 1;
        memcpy(g_sessions[s_idx].session_id, hdr->session_id, SESSION_ID_LEN);
        g_sessions[s_idx].last_seq = hdr->seq;
        g_sessions[s_idx].last_active = now;
        g_sessions[s_idx].pending_len = 0;
        g_sessions[s_idx].pending_off = 0;
        g_sessions[s_idx].pty_fd = -1;
        g_sessions[s_idx].pid = -1;
        g_sessions[s_idx].pty_closed = 0;
    }
    
    dnssh_session_t *sess = &g_sessions[s_idx];

    // Non-empty payload executes a command, empty payload pulls next output chunk.
    if (sess->pty_fd < 0 && !sess->pty_closed) {
        sess->pid = forkpty(&sess->pty_fd, NULL, NULL, NULL);
        if (sess->pid == 0) {
            setenv("TERM", "xterm-256color", 1);
            execlp("/bin/bash", "bash", "-i", NULL);
            execlp("/bin/sh", "sh", "-i", NULL);
            exit(1);
        } else if (sess->pid > 0) {
            int flags = fcntl(sess->pty_fd, F_GETFL, 0);
            fcntl(sess->pty_fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    if (decomp_len > 0 && sess->pty_fd >= 0 && !is_replay) {
        ssize_t w = write(sess->pty_fd, decomp, decomp_len);
        (void)w;
        // Optimization: Let the PTY produce some output immediately
        if (sess->pending_len <= sess->pending_off) {
            usleep(15000); // Increased to 15ms to snag more output locally in a single burst
            ssize_t n = read(sess->pty_fd, sess->pending_out, sizeof(sess->pending_out));
            if (n > 0) {
                sess->pending_len = n;
                sess->pending_off = 0;
            }
        }
    }

    {
        uint8_t response[512];
        size_t rlen = 0;
        size_t resp_len = 0;
        const uint8_t *resp_ptr = (const uint8_t *)"";

        if (is_replay && decomp_len > 0) {
            resp_ptr = (const uint8_t *)"";
            resp_len = 0;
        } else if (sess->pty_closed && sess->pending_off >= sess->pending_len) {
            resp_ptr = (const uint8_t *)"\xff\xff\xff\xff";
            resp_len = 4;
        } else if (sess->pending_off < sess->pending_len) {
            resp_ptr = sess->pending_out + sess->pending_off;
            resp_len = sess->pending_len - sess->pending_off;
        }

        // If output is too large for one DNS reply, shrink until it fits.
        while (resp_len > 0) {
            rlen = build_dns_txt_response(sess->session_id, packet, len, resp_ptr, resp_len, response, sizeof(response));
            if (rlen > 0) break;
            resp_len /= 2;
        }

        if (rlen == 0) {
            rlen = build_dns_txt_response(sess->session_id, packet, len, (const uint8_t *)"", 0, response, sizeof(response));
        }

        if (rlen > 0) {
            sendto(udp_sock, response, rlen, 0, (struct sockaddr*)client, sizeof(*client));
            if (resp_len > 0 && sess->pending_off < sess->pending_len) {
                sess->pending_off += resp_len;
                if (sess->pending_off > sess->pending_len) sess->pending_off = sess->pending_len;
            }
        }
    }

    free(plain); free(decomp);
    return;

reject:
    {
        uint8_t res[512];
        size_t rlen = len > 512 ? 512 : len;
        memcpy(res, packet, rlen);
        if (rlen >= 4) {
            res[2] |= 0x80; // QR = 1
            res[3] = (res[3] & 0xF0) | 0x05; // REFUSED
            res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = 0; // AN=NS=AR=0
            sendto(udp_sock, res, rlen, 0, (struct sockaddr*)client, sizeof(*client));
        }
    }
}

int main_server(int argc, char **argv) {
    // server mode accepts: <port> <domain> [key_hex_64]
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <port> <domain> [key_hex_64]\n", argv[0]);
        return 1;
    }
    if (parse_port_arg(argv[1], &g_server_port) != 0 || set_domain_arg(argv[2]) != 0) {
        fprintf(stderr, "Usage: %s <port> <domain> [key_hex_64]\n", argv[0]);
        return 1;
    }

    if (argc == 4) {
        if (parse_hex_key(argv[3], shared_key, KEY_LEN) != 0) {
            fprintf(stderr, "Invalid key: expected %u hex chars\n", (unsigned)(KEY_LEN * 2));
            return 1;
        }
    } else {
        randombytes_buf(shared_key, KEY_LEN);
        fprintf(stderr, "[DNSSH] No key supplied. Generated one-time key for this run.\n");
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    printf("[DNSSH] Server started on UDP/%u - Domain: %s (Build: %s)\n", (unsigned)g_server_port, g_domain, COMMIT_SHA);
    printf("Pre-shared key (hex): ");
    for (size_t i = 0; i < KEY_LEN; i++) printf("%02x", shared_key[i]);
    printf("\n");

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_server_port);
    if (bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind failed");
        return 1;
    }

    // If started as root via sudo, drop to the invoking user; otherwise keep root.
    if (getuid() == 0) {
        uid_t target_uid = 0;
        gid_t target_gid = 0;
        char target_user[64] = "root";
        char target_home[256] = "/root";
        char target_shell[256] = "/bin/bash";

        const char *sudo_uid = getenv("SUDO_UID");
        const char *sudo_gid = getenv("SUDO_GID");
        const char *sudo_user = getenv("SUDO_USER");

        if (sudo_uid && sudo_gid && sudo_user && *sudo_user) {
            unsigned long uid_ul;
            unsigned long gid_ul;
            if (parse_id_arg(sudo_uid, &uid_ul) == 0 && parse_id_arg(sudo_gid, &gid_ul) == 0) {
                target_uid = (uid_t)uid_ul;
                target_gid = (gid_t)gid_ul;
                snprintf(target_user, sizeof(target_user), "%s", sudo_user);

                if (lookup_user_in_passwd(sudo_user,
                                          &target_uid,
                                          &target_gid,
                                          target_home,
                                          sizeof(target_home),
                                          target_shell,
                                          sizeof(target_shell)) != 0) {
                    const char *env_home = getenv("HOME");
                    const char *env_shell = getenv("SHELL");
                    if (env_home && *env_home) snprintf(target_home, sizeof(target_home), "%s", env_home);
                    if (env_shell && *env_shell) snprintf(target_shell, sizeof(target_shell), "%s", env_shell);
                }
            }
        }

        if (target_uid != 0) {
            if (setgroups(1, &target_gid) != 0) perror("[WARN] setgroups failed");
            if (setgid(target_gid) != 0) perror("[WARN] setgid failed");
            if (setuid(target_uid) != 0) perror("[WARN] setuid failed");
            printf("[DNSSH] Dropped privileges to %s (uid=%u, gid=%u).\n",
                   target_user,
                   (unsigned)target_uid,
                   (unsigned)target_gid);
        } else {
            printf("[DNSSH] Running as root (no sudo caller detected).\n");
        }

        setenv("HOME", target_home, 1);
        setenv("USER", target_user, 1);
        setenv("LOGNAME", target_user, 1);
        setenv("SHELL", target_shell, 1);
        if (chdir(target_home) != 0) {
            perror("[WARN] chdir HOME failed");
            if (chdir("/") != 0) perror("[WARN] chdir / failed");
        }
    }

    uint8_t buf[4096];
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(udp_sock, &rfds);
        int max_fd = udp_sock;

        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].active && g_sessions[i].pty_fd >= 0) {
                FD_SET(g_sessions[i].pty_fd, &rfds);
                if (g_sessions[i].pty_fd > max_fd) max_fd = g_sessions[i].pty_fd;
            }
        }

        struct timeval tv = {0, 50000};
        if (select(max_fd + 1, &rfds, NULL, NULL, &tv) >= 0) {
            for (int i = 0; i < MAX_SESSIONS; i++) {
                dnssh_session_t *s = &g_sessions[i];
                if (s->active && s->pty_fd >= 0 && FD_ISSET(s->pty_fd, &rfds)) {
                    if (s->pending_off >= s->pending_len) {
                        s->pending_off = 0;
                        s->pending_len = 0;
                    }
                    while (s->pending_len < sizeof(s->pending_out)) {
                        ssize_t n = read(s->pty_fd, s->pending_out + s->pending_len, sizeof(s->pending_out) - s->pending_len);
                        if (n > 0) {
                            s->pending_len += n;
                        } else {
                            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                                close(s->pty_fd);
                                if (s->pid > 0) kill(s->pid, SIGKILL);
                                s->pty_fd = -1;
                                s->pty_closed = 1;
                            }
                            break;
                        }
                    }
                }
            }

            if (FD_ISSET(udp_sock, &rfds)) {
                struct sockaddr_in client;
                socklen_t clen = sizeof(client);
                ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&client, &clen);
                if (n > 0) {
                    handle_dns_query(buf, n, &client);
                }
            }
        }
    }
    return 0;
}

// ====================== MAIN ENTRY ======================
int main(int argc, char **argv) {
    // Make diagnostics visible immediately even when output is piped to tee/files.
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium failed\n");
        return 1;
    }

    // Load or generate shared key (demo only)
    randombytes_buf(shared_key, KEY_LEN);

#if defined(SERVER_ONLY) && !defined(CLIENT_ONLY)
    return main_server(argc, argv);
#elif defined(CLIENT_ONLY) && !defined(SERVER_ONLY)
    return main_client(argc, argv);
#else
    if (argc > 1 && strcmp(argv[1], "server") == 0) {
        if (argc != 4 && argc != 5) {
            fprintf(stderr, "Usage: %s server <port> <domain> [key_hex_64]\n", argv[0]);
            return 1;
        }
        return main_server(argc - 1, argv + 1);
    }
    return main_client(argc, argv);
#endif
}
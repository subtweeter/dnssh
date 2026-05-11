
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
        fprintf(stderr, "Usage: %s <domain> <key_hex_64> <resolver1> [resolver2] ...\n", argv[0]);
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

    struct sockaddr_in resolvers[MAX_RESOLVERS];
    int num_res = argc - 3;
    if (num_res > MAX_RESOLVERS) num_res = MAX_RESOLVERS;

    for (int i = 0; i < num_res; i++) {
        if (parse_resolver_arg(argv[i + 3], &resolvers[i]) != 0) {
            fprintf(stderr, "Invalid resolver (expected ip or ip:port): %s\n", argv[i + 3]);
            return 1;
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
    int current_res = 0;
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
            sendto(sock, query, qlen, 0, (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
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
                            sendto(sock, query, qlen, 0,
                                   (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
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
                        sendto(sock, query, qlen, 0,
                               (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
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
                    sendto(sock, query, qlen, 0,
                           (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
                    last_pull = now;
                }
            }

            // Retransmit the latest non-empty command packet if no response arrives.
            if (command_inflight && last_command_query_len > 0) {
                long resend_elapsed_us = (long)((now.tv_sec - last_command_send.tv_sec) * 1000000L +
                                                (now.tv_usec - last_command_send.tv_usec));
                if (resend_elapsed_us >= current_resend_interval_us) {
                    sendto(sock, last_command_query, last_command_query_len, 0,
                           (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
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
                sendto(sock, query, qlen, 0,
                       (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
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
                sendto(sock, query, qlen, 0,
                       (struct sockaddr*)&resolvers[current_res], sizeof(resolvers[0]));
            }
            last_heartbeat = time(NULL);
        }

        // resolver rotation on timeout (simple round-robin + backoff)
        if (waiting_for_command_output || !is_connected || command_inflight) {
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

            if (num_res > 1 && elapsed_sec >= current_switch_after_sec &&
                elapsed_since_switch >= current_switch_after_sec) {
                current_res = (current_res + 1) % num_res;
                last_resolver_switch = now;
                printf("[DNSSH] Switched resolver -> %s\r\n", inet_ntoa(resolvers[current_res].sin_addr));
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

        if (sess->pty_closed && sess->pending_off >= sess->pending_len) {
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
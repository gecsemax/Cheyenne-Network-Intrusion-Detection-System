// Cheyenne Network Intrusion System
// Author: Max Gecse
// File: cheyenne_nids.c
//
// Features:
// - TAP/SPAN-based passive NIDS using libpcap (multi-threaded)
// - Optional inline IPS mode using NFQUEUE (real drop/accept)
// - Optional high-speed capture mode using PF_RING
// - IPv4 + TCP/UDP/ICMP parsing
// - Snort-like rule engine (alert/drop/log, TCP/UDP/ICMP/IP, multiple content matches)
// - TCP SYN scan and ICMP ping sweep detection
// - HTTP request/response line parsing (TCP/80)
// - DNS over UDP and TCP with DNS tunneling heuristics
// - HTTPS (TLS) ClientHello SNI extraction (TCP/443)
// - JSON alerts + performance stats suitable for SIEM (e.g., Microsoft Sentinel)

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ctype.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <pfring.h>

#define SNAPLEN 65535
#define PROMISC 1
#define TIMEOUT_MS 1000

#define SYN_THRESHOLD 20
#define WINDOW_SECONDS 10

#define MAX_WORKERS 8
#define QUEUE_SIZE  4096

typedef enum {
    CAP_MODE_PCAP = 0,
    CAP_MODE_NFQ  = 1,
    CAP_MODE_PFRING = 2
} capture_mode_t;

static capture_mode_t g_cap_mode = CAP_MODE_PCAP;
static char *g_dev = NULL;
static uint16_t g_nfqueue_num = 0;

// ---------- performance stats ----------

typedef struct {
    unsigned long long pkt_total;
    unsigned long long pkt_alerted;
    unsigned long long pkt_dropped;
    unsigned long long bytes_total;
    unsigned long long rule_checks;
    double rule_avg_usec;
    time_t last_stats_ts;
} perf_stats_t;

static perf_stats_t g_stats;
static pthread_mutex_t g_stats_mtx = PTHREAD_MUTEX_INITIALIZER;

// ---------- TCP SYN scan tracking ----------

typedef struct {
    uint32_t src_ip;
    int syn_count;
    time_t first_seen;
} syn_tracker_t;

#define MAX_TRACKED 1024
static syn_tracker_t trackers[MAX_TRACKED];

// ---------- DNS tunneling heuristics ----------

#define DNS_TYPE_A     1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_NULL  10
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28

typedef struct {
    uint32_t src_ip;
    unsigned long total_queries;
    unsigned long long_qname_count;
    unsigned long high_entropy_labels;
    unsigned long txt_queries;
    unsigned long null_queries;
    unsigned long cname_queries;
    unsigned long a_aaaa_queries;
    unsigned long nxdomain_responses;
    time_t window_start;
} dns_src_stats_t;

#define MAX_DNS_SOURCES 1024
static dns_src_stats_t dns_sources[MAX_DNS_SOURCES];

#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;
#pragma pack(pop)

#define DOMAIN_HASH_SIZE 1024

typedef struct domain_entry {
    uint32_t src_ip;
    char base_domain[128];
    unsigned long unique_subdomains;
    time_t window_start;
    struct domain_entry *next;
} domain_entry_t;

static domain_entry_t *domain_hash[DOMAIN_HASH_SIZE];

static unsigned long hash_domain(uint32_t src_ip, const char *base) {
    unsigned long h = 5381;
    const unsigned char *p = (const unsigned char *)base;
    while (*p) {
        h = ((h << 5) + h) + *p++;
    }
    h ^= src_ip;
    return h % DOMAIN_HASH_SIZE;
}

static domain_entry_t *get_domain_entry(uint32_t src_ip, const char *base, time_t now) {
    unsigned long idx = hash_domain(src_ip, base);
    domain_entry_t *cur = domain_hash[idx];

    while (cur) {
        if (cur->src_ip == src_ip &&
            strncmp(cur->base_domain, base, sizeof(cur->base_domain)) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    domain_entry_t *e = (domain_entry_t *)calloc(1, sizeof(domain_entry_t));
    if (!e) return NULL;
    e->src_ip = src_ip;
    strncpy(e->base_domain, base, sizeof(e->base_domain) - 1);
    e->base_domain[sizeof(e->base_domain) - 1] = '\0';
    e->unique_subdomains = 0;
    e->window_start = now;
    e->next = domain_hash[idx];
    domain_hash[idx] = e;
    return e;
}

static void reset_domain_entry_if_needed(domain_entry_t *e, time_t now) {
    if (!e) return;
    if (e->window_start == 0 || (now - e->window_start) > WINDOW_SECONDS) {
        e->unique_subdomains = 0;
        e->window_start = now;
    }
}

// ---------- HTTPS SNI parsing ----------

static void parse_tls_client_hello(const u_char *payload, size_t len,
                                   const char *src_ip, uint16_t sport,
                                   const char *dst_ip, uint16_t dport) {
    if (len < 5)
        return;

    uint8_t content_type = payload[0];
    if (content_type != 0x16)
        return;

    size_t pos = 5;
    if (pos + 4 > len)
        return;

    uint8_t hs_type = payload[pos];
    if (hs_type != 0x01)
        return;
    pos += 4;

    if (pos + 34 > len)
        return;
    pos += 34;

    if (pos + 1 > len)
        return;
    uint8_t sid_len = payload[pos++];
    if (pos + sid_len > len)
        return;
    pos += sid_len;

    if (pos + 2 > len)
        return;
    uint16_t cs_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    if (pos + cs_len > len)
        return;
    pos += cs_len;

    if (pos + 1 > len)
        return;
    uint8_t cm_len = payload[pos++];
    if (pos + cm_len > len)
        return;
    pos += cm_len;

    if (pos + 2 > len)
        return;
    uint16_t ext_total_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    if (pos + ext_total_len > len)
        return;

    size_t ext_end = pos + ext_total_len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (payload[pos] << 8) | payload[pos + 1];
        uint16_t ext_len  = (payload[pos + 2] << 8) | payload[pos + 3];
        pos += 4;
        if (pos + ext_len > ext_end)
            break;

        if (ext_type == 0x0000) {
            size_t sn_pos = pos;
            if (sn_pos + 2 > pos + ext_len)
                break;
            uint16_t list_len = (payload[sn_pos] << 8) | payload[sn_pos + 1];
            sn_pos += 2;
            if (sn_pos + list_len > pos + ext_len)
                break;

            if (sn_pos + 3 > pos + ext_len)
                break;
            uint8_t  name_type = payload[sn_pos];
            uint16_t name_len  = (payload[sn_pos + 1] << 8) | payload[sn_pos + 2];
            sn_pos += 3;
            if (name_type == 0 && sn_pos + name_len <= pos + ext_len) {
                char sni[256];
                size_t cpy = name_len < sizeof(sni) - 1 ? name_len : sizeof(sni) - 1;
                memcpy(sni, &payload[sn_pos], cpy);
                sni[cpy] = '\0';

                printf("HTTPS SNI %s:%u -> %s:%u host=\"%s\"\n",
                       src_ip, sport, dst_ip, dport, sni);
                syslog(LOG_INFO, "HTTPS SNI %s:%u -> %s:%u host=\"%s\"",
                       src_ip, sport, dst_ip, dport, sni);
            }
            break;
        }
        pos += ext_len;
    }
}

// ---------- Snort-like rule engine ----------

typedef enum {
    RULE_ACTION_ALERT,
    RULE_ACTION_DROP,
    RULE_ACTION_LOG
} rule_action_t;

typedef struct {
    char *content;
    int nocase;
    int depth;
    int offset;
} rule_content_t;

#define MAX_RULE_CONTENT 4

typedef struct {
    rule_action_t action;
    int proto;
    uint32_t src_ip;
    uint32_t src_mask;
    uint16_t src_port;
    uint16_t dst_port;
    int any_src_port;
    int any_dst_port;
    int bidirectional;

    char msg[256];
    uint32_t sid;
    uint32_t rev;

    rule_content_t contents[MAX_RULE_CONTENT];
    int content_count;
} rule_t;

#define MAX_RULES 1024
static rule_t g_rules[MAX_RULES];
static int g_rule_count = 0;

static void trim(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static int parse_ip_any(const char *tok, uint32_t *ip, uint32_t *mask) {
    if (strcmp(tok, "any") == 0) {
        *ip = 0;
        *mask = 0;
        return 0;
    }
    return -1;
}

static int parse_port_any(const char *tok, uint16_t *port, int *any_port) {
    if (strcmp(tok, "any") == 0) {
        *port = 0;
        *any_port = 1;
        return 0;
    }
    int p = atoi(tok);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    *any_port = 0;
    return 0;
}

static rule_action_t parse_action(const char *tok) {
    if (strcmp(tok, "alert") == 0) return RULE_ACTION_ALERT;
    if (strcmp(tok, "drop")  == 0) return RULE_ACTION_DROP;
    if (strcmp(tok, "log")   == 0) return RULE_ACTION_LOG;
    return RULE_ACTION_ALERT;
}

static int parse_proto(const char *tok) {
    if (strcmp(tok, "tcp") == 0)  return IPPROTO_TCP;
    if (strcmp(tok, "udp") == 0)  return IPPROTO_UDP;
    if (strcmp(tok, "icmp") == 0) return IPPROTO_ICMP;
    if (strcmp(tok, "ip") == 0)   return 0;
    return 0;
}

static void init_rule(rule_t *r) {
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < MAX_RULE_CONTENT; i++) {
        r->contents[i].content = NULL;
        r->contents[i].nocase = 0;
        r->contents[i].depth = 0;
        r->contents[i].offset = 0;
    }
}

static int add_rule_content(rule_t *r, const char *s) {
    if (r->content_count >= MAX_RULE_CONTENT)
        return -1;
    size_t l = strlen(s);
    r->contents[r->content_count].content = (char *)malloc(l + 1);
    if (!r->contents[r->content_count].content)
        return -1;
    memcpy(r->contents[r->content_count].content, s, l + 1);
    r->content_count++;
    return 0;
}

static void load_rules_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Could not open rules file %s: %s\n", path, strerror(errno));
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (g_rule_count >= MAX_RULES)
            break;

        char *p = strchr(line, '(');
        if (!p) continue;
        char header[256];
        size_t header_len = (size_t)(p - line);
        if (header_len >= sizeof(header)) header_len = sizeof(header) - 1;
        memcpy(header, line, header_len);
        header[header_len] = '\0';

        char options_str[768];
        strncpy(options_str, p + 1, sizeof(options_str) - 1);
        options_str[sizeof(options_str) - 1] = '\0';
        char *rp = strrchr(options_str, ')');
        if (rp) *rp = '\0';

        char *saveptr = NULL;
        char *tok = strtok_r(header, " ", &saveptr);
        if (!tok) continue;

        rule_t r;
        init_rule(&r);
        r.action = parse_action(tok);

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        r.proto = parse_proto(tok);

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        if (parse_ip_any(tok, &r.src_ip, &r.src_mask) != 0) continue;

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        if (parse_port_any(tok, &r.src_port, &r.any_src_port) != 0) continue;

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        if (strcmp(tok, "->") == 0) {
            r.bidirectional = 0;
        } else if (strcmp(tok, "<>") == 0) {
            r.bidirectional = 1;
        } else {
            continue;
        }

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        if (parse_ip_any(tok, &r.src_ip, &r.src_mask) != 0) {
        }

        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) continue;
        if (parse_port_any(tok, &r.dst_port, &r.any_dst_port) != 0) continue;

        char *opt_save = NULL;
        char *opt = strtok_r(options_str, ";", &opt_save);
        rule_content_t *current_content = NULL;

        while (opt) {
            trim(opt);
            if (strncmp(opt, "msg:", 4) == 0) {
                char *q1 = strchr(opt + 4, '"');
                char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
                if (q1 && q2) {
                    size_t l = (size_t)(q2 - (q1 + 1));
                    if (l >= sizeof(r.msg)) l = sizeof(r.msg) - 1;
                    memcpy(r.msg, q1 + 1, l);
                    r.msg[l] = '\0';
                }
            } else if (strncmp(opt, "sid:", 4) == 0) {
                r.sid = (uint32_t)atoi(opt + 4);
            } else if (strncmp(opt, "rev:", 4) == 0) {
                r.rev = (uint32_t)atoi(opt + 4);
            } else if (strncmp(opt, "content:", 8) == 0) {
                char *q1 = strchr(opt + 8, '"');
                char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
                if (q1 && q2) {
                    char buf[512];
                    size_t l = (size_t)(q2 - (q1 + 1));
                    if (l >= sizeof(buf)) l = sizeof(buf) - 1;
                    memcpy(buf, q1 + 1, l);
                    buf[l] = '\0';
                    if (add_rule_content(&r, buf) == 0) {
                        current_content = &r.contents[r.content_count - 1];
                    }
                }
            } else if (strcmp(opt, "nocase") == 0) {
                if (current_content)
                    current_content->nocase = 1;
            } else if (strncmp(opt, "depth:", 6) == 0) {
                if (current_content)
                    current_content->depth = atoi(opt + 6);
            } else if (strncmp(opt, "offset:", 7) == 0) {
                if (current_content)
                    current_content->offset = atoi(opt + 7);
            }
            opt = strtok_r(NULL, ";", &opt_save);
        }

        g_rules[g_rule_count++] = r;
    }
    fclose(f);
    fprintf(stderr, "Loaded %d rules\n", g_rule_count);
}

// ---------- JSON logging helpers ----------

static void log_json_alert(const rule_t *r,
                           const struct ip *ip_hdr,
                           int proto,
                           uint16_t sport,
                           uint16_t dport,
                           const char *action) {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip_str, sizeof(dst_ip_str));

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    const char *proto_str = (proto == IPPROTO_TCP) ? "TCP" :
                            (proto == IPPROTO_UDP) ? "UDP" :
                            (proto == IPPROTO_ICMP) ? "ICMP" : "IP";

    fprintf(stdout,
        "{\"timestamp\":\"%s\",\"event_type\":\"alert\",\"action\":\"%s\","
        "\"src_ip\":\"%s\",\"src_port\":%u,"
        "\"dst_ip\":\"%s\",\"dst_port\":%u,"
        "\"proto\":\"%s\",\"rule_sid\":%u,\"rule_rev\":%u,"
        "\"rule_msg\":\"%s\"}\n",
        ts, action,
        src_ip_str, sport,
        dst_ip_str, dport,
        proto_str, r->sid, r->rev, r->msg);
    fflush(stdout);
}

static void log_json_stats(void) {
    pthread_mutex_lock(&g_stats_mtx);
    time_t now = time(NULL);
    if (g_stats.last_stats_ts == 0) {
        g_stats.last_stats_ts = now;
        pthread_mutex_unlock(&g_stats_mtx);
        return;
    }
    double interval = difftime(now, g_stats.last_stats_ts);
    if (interval < 5.0) {
        pthread_mutex_unlock(&g_stats_mtx);
        return;
    }

    double pps = g_stats.pkt_total / interval;
    double bps = g_stats.bytes_total * 8.0 / interval;

    struct tm tm;
    gmtime_r(&now, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    fprintf(stdout,
        "{\"timestamp\":\"%s\",\"event_type\":\"stats\","
        "\"pkt_total\":%llu,\"bytes_total\":%llu,"
        "\"pps\":%.2f,\"bps\":%.2f,"
        "\"pkt_alerted\":%llu,\"pkt_dropped\":%llu,"
        "\"rule_checks\":%llu,\"rule_avg_usec\":%.2f}\n",
        ts,
        (unsigned long long)g_stats.pkt_total,
        (unsigned long long)g_stats.bytes_total,
        pps, bps,
        (unsigned long long)g_stats.pkt_alerted,
        (unsigned long long)g_stats.pkt_dropped,
        (unsigned long long)g_stats.rule_checks,
        g_stats.rule_avg_usec);
    fflush(stdout);

    g_stats.last_stats_ts = now;
    g_stats.pkt_total = 0;
    g_stats.bytes_total = 0;
    g_stats.pkt_alerted = 0;
    g_stats.pkt_dropped = 0;
    g_stats.rule_checks = 0;
    pthread_mutex_unlock(&g_stats_mtx);
}

// ---------- payload match ----------

static int payload_match_one(const rule_content_t *c, const u_char *payload, size_t len) {
    if (!c->content) return 1;
    size_t clen = strlen(c->content);
    if (clen == 0) return 1;

    size_t start = c->offset > 0 ? (size_t)c->offset : 0;
    if (start >= len) return 0;
    size_t max_len = len - start;
    if (c->depth > 0 && (size_t)c->depth < max_len)
        max_len = (size_t)c->depth;

    for (size_t i = 0; i + clen <= max_len; i++) {
        const u_char *p = payload + start + i;
        int match = 1;
        for (size_t j = 0; j < clen; j++) {
            unsigned char a = p[j];
            unsigned char b = (unsigned char)c->content[j];
            if (c->nocase) {
                a = (unsigned char)tolower(a);
                b = (unsigned char)tolower(b);
            }
            if (a != b) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

static int payload_match_all(const rule_t *r, const u_char *payload, size_t len) {
    for (int i = 0; i < r->content_count; i++) {
        if (!payload_match_one(&r->contents[i], payload, len))
            return 0;
    }
    return 1;
}

typedef struct {
    int drop;
    const rule_t *rule;
} rule_result_t;

static rule_result_t apply_rules(int proto,
                                 const struct ip *ip_hdr,
                                 const u_char *app_payload,
                                 size_t app_payload_len) {
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    rule_result_t res;
    res.drop = 0;
    res.rule = NULL;

    uint16_t sport = 0, dport = 0;
    if (proto == IPPROTO_TCP) {
        const struct tcphdr *th = (const struct tcphdr *)app_payload;
        if ((const u_char *)th + sizeof(*th) > app_payload + app_payload_len)
            goto done;
        sport = ntohs(th->source);
        dport = ntohs(th->dest);
    } else if (proto == IPPROTO_UDP) {
        const struct udphdr *uh = (const struct udphdr *)app_payload;
        if ((const u_char *)uh + sizeof(*uh) > app_payload + app_payload_len)
            goto done;
        sport = ntohs(uh->uh_sport);
        dport = ntohs(uh->uh_dport);
    }

    for (int i = 0; i < g_rule_count; i++) {
        const rule_t *r = &g_rules[i];

        if (r->proto != 0 && r->proto != proto)
            continue;

        if (!r->any_src_port && sport != r->src_port)
            continue;
        if (!r->any_dst_port && dport != r->dst_port)
            continue;

        if (!payload_match_all(r, app_payload, app_payload_len))
            continue;

        res.rule = r;

        if (r->action == RULE_ACTION_ALERT || r->action == RULE_ACTION_LOG) {
            log_json_alert(r, ip_hdr, proto, sport, dport,
                           (r->action == RULE_ACTION_ALERT) ? "alert" : "log");
        }

        if (r->action == RULE_ACTION_DROP) {
            log_json_alert(r, ip_hdr, proto, sport, dport, "drop");
            res.drop = 1;
            break;
        }
    }

done:
    gettimeofday(&t2, NULL);
    double usec = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_usec - t1.tv_usec);

    pthread_mutex_lock(&g_stats_mtx);
    g_stats.rule_checks++;
    if (g_stats.rule_checks == 1) {
        g_stats.rule_avg_usec = usec;
    } else {
        g_stats.rule_avg_usec =
            (g_stats.rule_avg_usec * (g_stats.rule_checks - 1) + usec) /
            (double)g_stats.rule_checks;
    }
    if (res.rule) {
        g_stats.pkt_alerted++;
        if (res.drop) g_stats.pkt_dropped++;
    }
    pthread_mutex_unlock(&g_stats_mtx);

    return res;
}

// ---------- DNS stats helpers ----------

static dns_src_stats_t *get_dns_src(uint32_t src_ip) {
    int free_idx = -1;
    for (int i = 0; i < MAX_DNS_SOURCES; i++) {
        if (dns_sources[i].src_ip == src_ip)
            return &dns_sources[i];
        if (dns_sources[i].src_ip == 0 && free_idx == -1)
            free_idx = i;
    }
    if (free_idx == -1)
        return &dns_sources[0];
    dns_sources[free_idx].src_ip = src_ip;
    dns_sources[free_idx].total_queries = 0;
    dns_sources[free_idx].long_qname_count = 0;
    dns_sources[free_idx].high_entropy_labels = 0;
    dns_sources[free_idx].txt_queries = 0;
    dns_sources[free_idx].null_queries = 0;
    dns_sources[free_idx].cname_queries = 0;
    dns_sources[free_idx].a_aaaa_queries = 0;
    dns_sources[free_idx].nxdomain_responses = 0;
    dns_sources[free_idx].window_start = time(NULL);
    return &dns_sources[free_idx];
}

static void reset_dns_windows_if_needed(dns_src_stats_t *s, time_t now) {
    if (s->window_start == 0 || (now - s->window_start) > WINDOW_SECONDS) {
        s->total_queries = 0;
        s->long_qname_count = 0;
        s->high_entropy_labels = 0;
        s->txt_queries = 0;
        s->null_queries = 0;
        s->cname_queries = 0;
        s->a_aaaa_queries = 0;
        s->nxdomain_responses = 0;
        s->window_start = now;
    }
}

static int count_labels(const char *name) {
    int count = 0;
    const char *p = name;
    if (*p == '\0') return 0;
    count = 1;
    while (*p) {
        if (*p == '.')
            count++;
        p++;
    }
    return count;
}

static void compute_label_features(const char *sub, int *len,
                                   double *digit_ratio, double *unique_ratio) {
    int digits = 0;
    int total = 0;
    int seen[256] = {0};
    int unique = 0;

    for (const unsigned char *p = (const unsigned char *)sub; *p; p++) {
        unsigned char c = *p;
        if (isdigit(c))
            digits++;
        if (!seen[c]) {
            seen[c] = 1;
            unique++;
        }
        total++;
    }

    *len = total;
    *digit_ratio = (total > 0) ? (double)digits / (double)total : 0.0;
    *unique_ratio = (total > 0) ? (double)unique / (double)total : 0.0;
}

static void extract_base_and_sub(const char *name, char *base_out, size_t base_len,
                                 char *sub_out, size_t sub_len) {
    base_out[0] = '\0';
    sub_out[0] = '\0';

    char tmp[256];
    strncpy(tmp, name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *labels[32];
    int n = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(tmp, ".", &saveptr);
    while (tok && n < 32) {
        labels[n++] = tok;
        tok = strtok_r(NULL, ".", &saveptr);
    }

    if (n == 0)
        return;

    strncpy(sub_out, labels[0], sub_len - 1);
    sub_out[sub_len - 1] = '\0';

    if (n >= 2) {
        snprintf(base_out, base_len, "%s.%s",
                 labels[n - 2], labels[n - 1]);
    } else {
        strncpy(base_out, labels[0], base_len - 1);
        base_out[base_len - 1] = '\0';
    }
}

static void alert_dns(const char *msg, const char *src_ip) {
    printf("[ALERT][DNS] %s (src=%s)\n", msg, src_ip);
    syslog(LOG_WARNING, "[DNS] %s (src=%s)", msg, src_ip);
}

// ---------- SYN helpers ----------

static syn_tracker_t *find_or_create_tracker(uint32_t src_ip, time_t now) {
    int free_idx = -1;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (trackers[i].src_ip == src_ip)
            return &trackers[i];
        if (trackers[i].src_ip == 0 && free_idx == -1)
            free_idx = i;
    }
    if (free_idx == -1)
        return NULL;
    trackers[free_idx].src_ip = src_ip;
    trackers[free_idx].syn_count = 0;
    trackers[free_idx].first_seen = now;
    return &trackers[free_idx];
}

static void maybe_expire_trackers(time_t now) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (trackers[i].src_ip != 0 &&
            (now - trackers[i].first_seen) > WINDOW_SECONDS) {
            trackers[i].src_ip = 0;
            trackers[i].syn_count = 0;
            trackers[i].first_seen = 0;
        }
    }
}

// ---------- HTTP parsing ----------

static void parse_http(const u_char *payload, size_t len,
                       const char *src_ip, uint16_t sport,
                       const char *dst_ip, uint16_t dport) {
    size_t max_scan = len < 2048 ? len : 2048;
    char buf[2049];
    memcpy(buf, payload, max_scan);
    buf[max_scan] = '\0';

    char *line_end = strstr(buf, "\r\n");
    if (!line_end)
        return;
    *line_end = '\0';

    printf("HTTP %s -> %s (%u->%u): \"%s\"\n",
           src_ip, dst_ip, sport, dport, buf);
}

// ---------- DNS parsing + tunneling heuristics ----------

static void parse_dns(const u_char *payload, size_t len,
                      const char *src_ip, uint32_t src_ip_raw,
                      uint16_t sport, const char *dst_ip, uint16_t dport) {
    (void)sport;
    (void)dst_ip;
    (void)dport;

    if (len < sizeof(dns_header_t))
        return;

    const dns_header_t *hdr = (const dns_header_t *)payload;
    uint16_t flags = ntohs(hdr->flags);
    uint16_t qdcount = ntohs(hdr->qdcount);
    int qr = (flags & 0x8000) ? 1 : 0;
    int rcode = flags & 0xF;

    const u_char *p = payload + sizeof(dns_header_t);
    const u_char *end = payload + len;

    char name[256];
    name[0] = '\0';

    uint16_t qtype = 0, qclass = 0;

    if (qdcount > 0) {
        int i = 0;
        while (p < end && *p != 0 && i < (int)sizeof(name) - 1) {
            uint8_t label_len = *p++;
            if (label_len == 0 || p + label_len > end)
                break;
            if (i != 0)
                name[i++] = '.';
            memcpy(&name[i], p, label_len);
            i += label_len;
            p += label_len;
        }
        name[i] = '\0';
        if (p < end && *p == 0)
            p++;
        if (p + 4 <= end) {
            qtype = ntohs(*(const uint16_t *)p);
            qclass = ntohs(*(const uint16_t *)(p + 2));
        }
        (void)qclass;
    }

    time_t now = time(NULL);
    dns_src_stats_t *src_stats = get_dns_src(src_ip_raw);
    reset_dns_windows_if_needed(src_stats, now);
    src_stats->total_queries++;

    if (qr == 1 && rcode == 3) {
        src_stats->nxdomain_responses++;
        if (src_stats->nxdomain_responses > 50 &&
            (now - src_stats->window_start) <= WINDOW_SECONDS) {
            alert_dns("DNS: many NXDOMAIN responses (possible tunneling/DGA)", src_ip);
        }
    }

    if (qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA) {
        src_stats->a_aaaa_queries++;
    } else if (qtype == DNS_TYPE_TXT) {
        src_stats->txt_queries++;
    } else if (qtype == DNS_TYPE_NULL) {
        src_stats->null_queries++;
    } else if (qtype == DNS_TYPE_CNAME) {
        src_stats->cname_queries++;
    }

    unsigned long unusual = src_stats->txt_queries +
                             src_stats->null_queries +
                             src_stats->cname_queries;
    unsigned long total = src_stats->total_queries;
    if (total > 100 &&
        unusual > total / 2 &&
        (now - src_stats->window_start) <= WINDOW_SECONDS) {
        alert_dns("DNS: unusual RR type mix (TXT/NULL/CNAME heavy)", src_ip);
    }

    if (name[0] != '\0') {
        size_t name_len = strlen(name);
        int labels = count_labels(name);
        if (name_len > 52 || labels > 5) {
            src_stats->long_qname_count++;
            if (src_stats->long_qname_count > 100 &&
                (now - src_stats->window_start) <= WINDOW_SECONDS) {
                alert_dns("DNS: many long/multi-label queries (possible tunneling)", src_ip);
            }
        }

        char base[128];
        char sub[128];
        extract_base_and_sub(name, base, sizeof(base), sub, sizeof(sub));

        if (base[0] != '\0') {
            domain_entry_t *dom = get_domain_entry(src_ip_raw, base, now);
            reset_domain_entry_if_needed(dom, now);
            if (dom) {
                dom->unique_subdomains++;
                if (dom->unique_subdomains > 500 &&
                    (now - dom->window_start) <= WINDOW_SECONDS) {
                    alert_dns("DNS: many unique subdomains under one domain", src_ip);
                }
            }
        }

        if (sub[0] != '\0') {
            int sub_len;
            double digit_ratio, unique_ratio;
            compute_label_features(sub, &sub_len, &digit_ratio, &unique_ratio);
            if (sub_len > 20 && digit_ratio > 0.3 && unique_ratio > 0.6) {
                src_stats->high_entropy_labels++;
                if (src_stats->high_entropy_labels > 50 &&
                    (now - src_stats->window_start) <= WINDOW_SECONDS) {
                    alert_dns("DNS: high-entropy subdomains (possible tunneling)", src_ip);
                }
            }
        }
    }

    if (src_stats->total_queries > 1000 &&
        (now - src_stats->window_start) <= WINDOW_SECONDS) {
        alert_dns("DNS: high query volume from single host", src_ip);
    }
}

// ---------- TCP/UDP/ICMP handlers (passive/NFQ use same logic) ----------

static void handle_tcp(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr,
                       const u_char *packet_base, const struct pcap_pkthdr *h) {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip_str, sizeof(dst_ip_str));

    uint16_t sport = ntohs(tcp_hdr->source);
    uint16_t dport = ntohs(tcp_hdr->dest);

    uint8_t tcp_hdr_len = tcp_hdr->doff * 4;
    const u_char *payload = (const u_char *)tcp_hdr + tcp_hdr_len;
    const u_char *packet_end = packet_base + h->caplen;
    size_t payload_len = 0;
    if (payload <= packet_end)
        payload_len = (size_t)(packet_end - payload);

    rule_result_t rres = apply_rules(IPPROTO_TCP, ip_hdr, payload, payload_len);
    if (rres.drop && g_cap_mode == CAP_MODE_PCAP) {
        printf("[DROP/passive] TCP %s:%u -> %s:%u by rule sid=%u\n",
               src_ip_str, sport, dst_ip_str, dport,
               rres.rule ? rres.rule->sid : 0);
        syslog(LOG_WARNING, "[DROP/passive] TCP %s:%u -> %s:%u by rule sid=%u",
               src_ip_str, sport, dst_ip_str, dport,
               rres.rule ? rres.rule->sid : 0);
        return;
    }

    if (tcp_hdr->syn && !tcp_hdr->ack) {
        time_t now = h->ts.tv_sec;
        maybe_expire_trackers(now);
        uint32_t src_ip = ip_hdr->ip_src.s_addr;
        syn_tracker_t *tr = find_or_create_tracker(src_ip, now);
        if (tr) {
            if (tr->syn_count == 0)
                tr->first_seen = now;
            tr->syn_count++;
            if (tr->syn_count == SYN_THRESHOLD) {
                printf("[ALERT] Possible SYN scan from %s: %d SYN in %d s\n",
                       src_ip_str, tr->syn_count, WINDOW_SECONDS);
                syslog(LOG_WARNING, "SYN scan from %s: %d SYN in %d s",
                       src_ip_str, tr->syn_count, WINDOW_SECONDS);
            }
        }
    }

    if (payload_len > 0 && (sport == 80 || dport == 80)) {
        parse_http(payload, payload_len, src_ip_str, sport, dst_ip_str, dport);
    }

    if (payload_len > 2 && (sport == 53 || dport == 53)) {
        uint16_t dns_len = (payload[0] << 8) | payload[1];
        if (dns_len + 2 <= payload_len) {
            const u_char *dns_payload = payload + 2;
            parse_dns(dns_payload, dns_len,
                      src_ip_str, ip_hdr->ip_src.s_addr,
                      sport, dst_ip_str, dport);
        }
    }

    if (payload_len > 0 && (sport == 443 || dport == 443)) {
        parse_tls_client_hello(payload, payload_len,
                               src_ip_str, sport, dst_ip_str, dport);
    }
}

static void handle_udp(const struct ip *ip_hdr, const struct udphdr *udp_hdr,
                       const u_char *packet_base) {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip_str, sizeof(dst_ip_str));

    uint16_t sport = ntohs(udp_hdr->uh_sport);
    uint16_t dport = ntohs(udp_hdr->uh_dport);

    const u_char *ip_start = packet_base + sizeof(struct ether_header);
    uint32_t ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_start = ip_start + ip_header_len;
    const u_char *payload = udp_start + sizeof(struct udphdr);

    uint16_t udp_len = ntohs(udp_hdr->uh_ulen);
    if (udp_len <= sizeof(struct udphdr))
        return;
    size_t payload_len = udp_len - sizeof(struct udphdr);

    rule_result_t rres = apply_rules(IPPROTO_UDP, ip_hdr, payload, payload_len);
    if (rres.drop && g_cap_mode == CAP_MODE_PCAP) {
        printf("[DROP/passive] UDP %s:%u -> %s:%u by rule sid=%u\n",
               src_ip_str, sport, dst_ip_str, dport,
               rres.rule ? rres.rule->sid : 0);
        syslog(LOG_WARNING, "[DROP/passive] UDP %s:%u -> %s:%u by rule sid=%u",
               src_ip_str, sport, dst_ip_str, dport,
               rres.rule ? rres.rule->sid : 0);
        return;
    }

    if (sport == 53 || dport == 53) {
        parse_dns(payload, payload_len,
                  src_ip_str, ip_hdr->ip_src.s_addr,
                  sport, dst_ip_str, dport);
    }
}

static void handle_icmp(const struct ip *ip_hdr, const struct icmphdr *icmp_hdr) {
    (void)ip_hdr;

    static int echo_count = 0;
    static time_t window_start = 0;
    time_t now = time(NULL);

    if (window_start == 0)
        window_start = now;
    if (now - window_start > WINDOW_SECONDS) {
        echo_count = 0;
        window_start = now;
    }

    if (icmp_hdr->type == ICMP_ECHO) {
        echo_count++;
        if (echo_count == 50) {
            printf("[ALERT] Possible ICMP ping sweep (%d echo in %d s)\n",
                   echo_count, WINDOW_SECONDS);
            syslog(LOG_WARNING, "ICMP ping sweep: %d echo in %d s",
                   echo_count, WINDOW_SECONDS);
        }
    }
}

// ---------- worker-side packet handler ----------

static void process_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    pthread_mutex_lock(&g_stats_mtx);
    g_stats.pkt_total++;
    g_stats.bytes_total += h->caplen;
    pthread_mutex_unlock(&g_stats_mtx);

    if (h->caplen < sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    const u_char *ip_start = bytes + sizeof(struct ether_header);
    if (ip_start + sizeof(struct ip) > bytes + h->caplen)
        return;

    const struct ip *ip_hdr = (const struct ip *)ip_start;
    uint8_t proto = ip_hdr->ip_p;
    uint32_t ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *l4_start = ip_start + ip_header_len;
    if (l4_start > bytes + h->caplen)
        return;

    switch (proto) {
        case IPPROTO_TCP: {
            if (l4_start + sizeof(struct tcphdr) > bytes + h->caplen)
                return;
            const struct tcphdr *tcp_hdr = (const struct tcphdr *)l4_start;
            handle_tcp(ip_hdr, tcp_hdr, bytes, h);
            break;
        }
        case IPPROTO_UDP: {
            if (l4_start + sizeof(struct udphdr) > bytes + h->caplen)
                return;
            const struct udphdr *udp_hdr = (const struct udphdr *)l4_start;
            handle_udp(ip_hdr, udp_hdr, bytes);
            break;
        }
        case IPPROTO_ICMP: {
            if (l4_start + sizeof(struct icmphdr) > bytes + h->caplen)
                return;
            const struct icmphdr *icmp_hdr = (const struct icmphdr *)l4_start;
            handle_icmp(ip_hdr, icmp_hdr);
            break;
        }
        default:
            break;
    }
}

// ---------- packet queue + workers (pcap) ----------

typedef struct {
    struct pcap_pkthdr hdr;
    u_char *data;
} packet_t;

typedef struct {
    packet_t ring[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mtx;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
    int stop;
} packet_queue_t;

static packet_queue_t g_queue;
static int g_worker_count = 4;

static void queue_init(packet_queue_t *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mtx, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

static void queue_destroy(packet_queue_t *q) {
    pthread_mutex_destroy(&q->mtx);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

static void queue_push(packet_queue_t *q, const struct pcap_pkthdr *h, const u_char *bytes) {
    pthread_mutex_lock(&q->mtx);
    while (q->count == QUEUE_SIZE && !q->stop) {
        pthread_cond_wait(&q->not_full, &q->mtx);
    }
    if (q->stop) {
        pthread_mutex_unlock(&q->mtx);
        return;
    }
    int idx = q->tail;
    q->ring[idx].hdr = *h;
    q->ring[idx].data = (u_char *)malloc(h->caplen);
    memcpy(q->ring[idx].data, bytes, h->caplen);
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mtx);
}

static int queue_pop(packet_queue_t *q, packet_t *out) {
    pthread_mutex_lock(&q->mtx);
    while (q->count == 0 && !q->stop) {
        pthread_cond_wait(&q->not_empty, &q->mtx);
    }
    if (q->count == 0 && q->stop) {
        pthread_mutex_unlock(&q->mtx);
        return 0;
    }
    int idx = q->head;
    *out = q->ring[idx];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mtx);
    return 1;
}

static void queue_stop(packet_queue_t *q) {
    pthread_mutex_lock(&q->mtx);
    q->stop = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mtx);
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    queue_push(&g_queue, h, bytes);
}

static void *worker_thread(void *arg) {
    (void)arg;
    packet_t pkt;
    while (queue_pop(&g_queue, &pkt)) {
        process_packet(&pkt.hdr, pkt.data);
        free(pkt.data);
    }
    return NULL;
}

// ---------- NFQUEUE inline inspect ----------

static int inspect_ip_packet(uint8_t proto,
                             const u_char *pkt,
                             uint32_t pkt_len) {
    struct pcap_pkthdr h;
    memset(&h, 0, sizeof(h));
    h.caplen = pkt_len + sizeof(struct ether_header);
    h.len = h.caplen;
    h.ts.tv_sec = time(NULL);

    u_char *buf = (u_char *)malloc(h.caplen);
    if (!buf) return 0;
    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth, 0, sizeof(*eth));
    eth->ether_type = htons(ETHERTYPE_IP);
    memcpy(buf + sizeof(struct ether_header), pkt, pkt_len);

    const struct ip *ip_hdr = (const struct ip *)pkt;
    const u_char *ip_start = pkt;
    uint32_t ip_header_len = ip_hdr->ip_hl * 4;
    if (pkt_len < ip_header_len) {
        free(buf);
        return 0;
    }
    const u_char *l4 = ip_start + ip_header_len;
    int drop = 0;

    if (proto == IPPROTO_TCP) {
        if ((size_t)(l4 - pkt) + sizeof(struct tcphdr) > pkt_len) {
            free(buf);
            return 0;
        }
        const struct tcphdr *th = (const struct tcphdr *)l4;
        uint8_t tcp_hdr_len = th->doff * 4;
        const u_char *payload = (const u_char *)th + tcp_hdr_len;
        if ((size_t)(payload - pkt) > pkt_len) {
            free(buf);
            return 0;
        }
        size_t payload_len = pkt_len - (size_t)(payload - pkt);
        rule_result_t rres = apply_rules(IPPROTO_TCP, ip_hdr, payload, payload_len);
        if (rres.drop) {
            drop = 1;
        }
    } else if (proto == IPPROTO_UDP) {
        if ((size_t)(l4 - pkt) + sizeof(struct udphdr) > pkt_len) {
            free(buf);
            return 0;
        }
        const struct udphdr *uh = (const struct udphdr *)l4;
        const u_char *payload = (const u_char *)uh + sizeof(struct udphdr);
        if ((size_t)(payload - pkt) > pkt_len) {
            free(buf);
            return 0;
        }
        size_t payload_len = pkt_len - (size_t)(payload - pkt);
        rule_result_t rres = apply_rules(IPPROTO_UDP, ip_hdr, payload, payload_len);
        if (rres.drop) {
            drop = 1;
        }
    }

    if (!drop) {
        process_packet(&h, buf);
    }

    free(buf);
    return drop;
}

static int nfq_cb(struct nfq_q_handle *qh,
                  struct nfgenmsg *nfmsg,
                  struct nfq_data *nfa,
                  void *data) {
    (void)nfmsg;
    (void)data;

    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    unsigned char *packet = NULL;
    int len = nfq_get_payload(nfa, &packet);
    if (len < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    if (len < (int)sizeof(struct ip)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    struct ip *ip_hdr = (struct ip *)packet;
    uint8_t proto = ip_hdr->ip_p;

    int drop = inspect_ip_packet(proto, packet, (uint32_t)len);

    if (drop) {
        pthread_mutex_lock(&g_stats_mtx);
        g_stats.pkt_dropped++;
        pthread_mutex_unlock(&g_stats_mtx);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    } else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

// ---------- PF_RING capture ----------

static int run_pfring_capture(const char *iface) {
    pfring *ring;
    int rc;

    ring = pfring_open(iface, SNAPLEN, PF_RING_PROMISC);
    if (!ring) {
        fprintf(stderr, "pfring_open(%s) failed\n", iface);
        return 1;
    }

    pfring_set_direction(ring, rx_only_direction);
    pfring_enable_ring(ring);

    printf("Cheyenne NIDS PF_RING capture on %s...\n", iface);
    syslog(LOG_INFO, "Cheyenne NIDS PF_RING capture on %s", iface);

    while (1) {
        u_char *pkt = NULL;
        struct pfring_pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));

        rc = pfring_recv(ring, &pkt, 0, &hdr, 1);
        if (rc <= 0) {
            continue;
        }

        struct pcap_pkthdr ph;
        memset(&ph, 0, sizeof(ph));
        ph.caplen = hdr.caplen;
        ph.len    = hdr.len;
        ph.ts.tv_sec  = hdr.ts.tv_sec;
        ph.ts.tv_usec = hdr.ts.tv_usec;

        process_packet(&ph, pkt);
        log_json_stats();
    }

    pfring_disable_ring(ring);
    pfring_close(ring);
    return 0;
}

// ---------- signal handling ----------

static volatile sig_atomic_t g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

// ---------- main ----------

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Cheyenne Network Intrusion System\n");
        fprintf(stderr, "Author: Max Gecse\n");
        fprintf(stderr, "Usage (pcap):   %s <tap_interface> [rules] [workers]\n", argv[0]);
        fprintf(stderr, "Usage (NFQUEUE):%s nfq [rules] [workers] [queue_num]\n", argv[0]);
        fprintf(stderr, "Usage (PF_RING):%s pfring:<iface> [rules] [workers]\n", argv[0]);
        return 1;
    }

    char *mode = argv[1];

    if (strncmp(mode, "nfq", 3) == 0) {
        g_cap_mode = CAP_MODE_NFQ;
    } else if (strncmp(mode, "pfring:", 7) == 0) {
        g_cap_mode = CAP_MODE_PFRING;
        g_dev = mode + 7;
    } else {
        g_cap_mode = CAP_MODE_PCAP;
        g_dev = argv[1];
    }

    if (argc >= 3) {
        load_rules_from_file(argv[2]);
    }
    if (argc >= 4) {
        int n = atoi(argv[3]);
        if (n > 0 && n <= MAX_WORKERS) g_worker_count = n;
    }
    if (g_cap_mode == CAP_MODE_NFQ && argc >= 5) {
        g_nfqueue_num = (uint16_t)atoi(argv[4]);
    } else if (g_cap_mode == CAP_MODE_NFQ) {
        g_nfqueue_num = 0;
    }

    memset(&g_stats, 0, sizeof(g_stats));
    memset(trackers, 0, sizeof(trackers));
    memset(dns_sources, 0, sizeof(dns_sources));
    memset(domain_hash, 0, sizeof(domain_hash));

    openlog("cheyenne_nids", LOG_PID | LOG_CONS, LOG_USER);
    signal(SIGINT, handle_sigint);

    if (g_cap_mode == CAP_MODE_NFQ) {
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        h = nfq_open();
        if (!h) {
            fprintf(stderr, "nfq_open() failed\n");
            return 1;
        }

        nfq_unbind_pf(h, AF_INET);
        if (nfq_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "nfq_bind_pf() failed\n");
            nfq_close(h);
            return 1;
        }

        qh = nfq_create_queue(h, g_nfqueue_num, &nfq_cb, NULL);
        if (!qh) {
            fprintf(stderr, "nfq_create_queue() failed\n");
            nfq_close(h);
            return 1;
        }

        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "nfq_set_mode() failed\n");
            nfq_destroy_queue(qh);
            nfq_close(h);
            return 1;
        }

        fd = nfq_fd(h);
        printf("Cheyenne NIDS inline NFQUEUE mode on queue %u\n", g_nfqueue_num);
        syslog(LOG_INFO, "Cheyenne NIDS inline NFQUEUE mode on queue %u", g_nfqueue_num);

        while (g_running && (rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            log_json_stats();
        }

        nfq_destroy_queue(qh);
        nfq_close(h);
        closelog();
        return 0;
    }

    if (g_cap_mode == CAP_MODE_PFRING) {
        int ret = run_pfring_capture(g_dev);
        closelog();
        return ret;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(g_dev, SNAPLEN, PROMISC, TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed on %s: %s\n", g_dev, errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    printf("Cheyenne Network Intrusion System starting on %s (pcap)...\n", g_dev);
    printf("Author: Max Gecse\n");
    syslog(LOG_INFO, "Cheyenne NIDS started on %s (pcap)", g_dev);

    queue_init(&g_queue);

    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < g_worker_count; i++) {
        pthread_create(&workers[i], NULL, worker_thread, NULL);
    }

    while (g_running) {
        int ret = pcap_dispatch(handle, -1, pcap_callback, NULL);
        if (ret < 0) {
            if (g_running) {
                fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
            }
            break;
        }
        log_json_stats();
    }

    queue_stop(&g_queue);
    for (int i = 0; i < g_worker_count; i++) {
        pthread_join(workers[i], NULL);
    }
    queue_destroy(&g_queue);

    pcap_close(handle);
    closelog();
    return 0;
}

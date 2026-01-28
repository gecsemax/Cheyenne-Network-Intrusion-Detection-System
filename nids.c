// Cheyenne Network Intrusion System
// Author: Max Gecse
// File: cheyenne_nids.c
//
// Features:
// - TAP/SPAN-based passive NIDS using libpcap
// - IPv4 + TCP/UDP/ICMP parsing
// - TCP SYN scan and ICMP ping sweep detection
// - HTTP request/response line parsing (TCP/80)
// - DNS over UDP and TCP with DNS tunneling heuristics
// - HTTPS (TLS) ClientHello SNI extraction (TCP/443)
// - Alerts to stdout and syslog (for SIEM integration)

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

#define SNAPLEN 65535
#define PROMISC 1
#define TIMEOUT_MS 1000

#define SYN_THRESHOLD 20
#define WINDOW_SECONDS 10  // tune this for real deployments

// ---------- TCP SYN scan tracking ----------

typedef struct {
    uint32_t src_ip;
    int syn_count;
    time_t first_seen;
} syn_tracker_t;

#define MAX_TRACKED 1024
static syn_tracker_t trackers[MAX_TRACKED];

// ---------- DNS tunneling heuristics ----------

// DNS RR types (subset)
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

// ---------- Simple hash table for per-(src, base domain) uniqueness ----------

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
    unsigned long h = 5381; // djb2-style hash
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

// ---------- HTTPS metadata: TLS ClientHello SNI parsing ----------

static void parse_tls_client_hello(const u_char *payload, size_t len,
                                   const char *src_ip, uint16_t sport,
                                   const char *dst_ip, uint16_t dport) {
    if (len < 5)
        return;

    uint8_t content_type = payload[0];
    if (content_type != 0x16) // 22 = handshake
        return;

    size_t pos = 5; // skip record header
    if (pos + 4 > len)
        return;

    uint8_t hs_type = payload[pos];
    if (hs_type != 0x01) // ClientHello
        return;
    pos += 4; // handshake header (type + length)

    // skip version(2) + random(32)
    if (pos + 34 > len)
        return;
    pos += 34;

    // Session ID
    if (pos + 1 > len)
        return;
    uint8_t sid_len = payload[pos++];
    if (pos + sid_len > len)
        return;
    pos += sid_len;

    // Cipher suites
    if (pos + 2 > len)
        return;
    uint16_t cs_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    if (pos + cs_len > len)
        return;
    pos += cs_len;

    // Compression methods
    if (pos + 1 > len)
        return;
    uint8_t cm_len = payload[pos++];
    if (pos + cm_len > len)
        return;
    pos += cm_len;

    // Extensions
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

        if (ext_type == 0x0000) { // server_name extension
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

// ---------- prototypes ----------

static void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
static void handle_tcp(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr,
                       const u_char *packet_base, const struct pcap_pkthdr *h);
static void handle_udp(const struct ip *ip_hdr, const struct udphdr *udp_hdr,
                       const u_char *packet_base);
static void handle_icmp(const struct ip *ip_hdr, const struct icmphdr *icmp_hdr);

static void parse_http(const u_char *payload, size_t len,
                       const char *src_ip, uint16_t sport,
                       const char *dst_ip, uint16_t dport);
static void parse_dns(const u_char *payload, size_t len,
                      const char *src_ip, uint32_t src_ip_raw,
                      uint16_t sport, const char *dst_ip, uint16_t dport);

// DNS stats helpers
static dns_src_stats_t *get_dns_src(uint32_t src_ip);
static void reset_dns_windows_if_needed(dns_src_stats_t *s, time_t now);
static int count_labels(const char *name);
static void compute_label_features(const char *sub, int *len, double *digit_ratio,
                                   double *unique_ratio);
static void extract_base_and_sub(const char *name, char *base_out, size_t base_len,
                                 char *sub_out, size_t sub_len);
static void alert_dns(const char *msg, const char *src_ip);

// SYN helpers
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

// ---------- main ----------

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Cheyenne Network Intrusion System\n");
        fprintf(stderr, "Author: Max Gecse\n");
        fprintf(stderr, "Usage: %s <tap_interface>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    memset(trackers, 0, sizeof(trackers));
    memset(dns_sources, 0, sizeof(dns_sources));
    memset(domain_hash, 0, sizeof(domain_hash));

    openlog("cheyenne_nids", LOG_PID | LOG_CONS, LOG_USER);

    handle = pcap_open_live(dev, SNAPLEN, PROMISC, TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed on %s: %s\n", dev, errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "ip"; // capture all IPv4
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

    printf("Cheyenne Network Intrusion System starting on %s...\n", dev);
    printf("Author: Max Gecse\n");
    syslog(LOG_INFO, "Cheyenne NIDS started on %s", dev);

    pcap_loop(handle, 0, handle_packet, NULL);

    pcap_close(handle);
    closelog();
    return 0;
}

// ---------- packet dispatch ----------

static void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;

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

    // SYN scan detection
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

    // HTTP parsing on port 80
    if (payload_len > 0 && (sport == 80 || dport == 80)) {
        parse_http(payload, payload_len, src_ip_str, sport, dst_ip_str, dport);
    }

    // DNS over TCP (port 53)
    if (payload_len > 2 && (sport == 53 || dport == 53)) {
        uint16_t dns_len = (payload[0] << 8) | payload[1];
        if (dns_len + 2 <= payload_len) {
            const u_char *dns_payload = payload + 2;
            parse_dns(dns_payload, dns_len,
                      src_ip_str, ip_hdr->ip_src.s_addr,
                      sport, dst_ip_str, dport);
        }
    }

    // HTTPS SNI (TLS ClientHello) on port 443
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
    (void)payload_len;

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

// ---------- HTTP parsing ----------

static void parse_http(const u_char *payload, size_t len,
                       const char *src_ip, uint16_t sport,
                       const char *dst_ip, uint16_t dport) {
    size_t max_scan = len < 1024 ? len : 1024;
    char buf[1025];
    memcpy(buf, payload, max_scan);
    buf[max_scan] = '\0';

    char *line_end = strstr(buf, "\r\n");
    if (!line_end)
        return;
    *line_end = '\0';

    if (strncmp(buf, "GET ", 4) == 0 ||
        strncmp(buf, "POST ", 5) == 0 ||
        strncmp(buf, "HEAD ", 5) == 0 ||
        strncmp(buf, "PUT ", 4) == 0 ||
        strncmp(buf, "DELETE ", 7) == 0 ||
        strncmp(buf, "OPTIONS ", 8) == 0) {

        printf("HTTP request %s -> %s (%u->%u): \"%s\"\n",
               src_ip, dst_ip, sport, dport, buf);
    } else if (strncmp(buf, "HTTP/", 5) == 0) {
        printf("HTTP response %s -> %s (%u->%u): \"%s\"\n",
               src_ip, dst_ip, sport, dport, buf);
    }
}

// ---------- DNS parsing + tunneling heuristics ----------

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
    int rcode = flags & 0xF; // 3 = NXDOMAIN

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

    // NXDOMAIN tracking
    if (qr == 1 && rcode == 3) {
        src_stats->nxdomain_responses++;
        if (src_stats->nxdomain_responses > 50 &&
            (now - src_stats->window_start) <= WINDOW_SECONDS) {
            alert_dns("DNS: many NXDOMAIN responses (possible tunneling/DGA)", src_ip);
        }
    }

    // RR type mix
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

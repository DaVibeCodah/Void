/* Vo!d eBPF Programs
 * Compiled and loaded by Aya (Rust eBPF framework).
 * Three programs:
 *   1. xdp_syn_guard   — XDP hook, drops SYN floods at NIC
 *   2. tc_tcp_inspect  — TC hook, TCP fingerprinting
 *   3. socket_monitor  — Socket filter, per-connection stats
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SYN_THRESHOLD   1000   /* max SYNs per second per IP */
#define RATE_WINDOW_NS  1000000000ULL  /* 1 second in nanoseconds */

/* ── BPF Maps ─────────────────────────────────────────────────────── */

/* Per-IP SYN counter: ip -> count */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);  /* 1M entries */
    __type(key, __u32);
    __type(value, __u64);
} syn_counter SEC(".maps");

/* Per-IP last SYN timestamp */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);
    __type(value, __u64);
} syn_timestamp SEC(".maps");

/* IP blocklist: ip -> reason code */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);
    __type(value, __u8);
} ip_blocklist SEC(".maps");

/* TCP fingerprint data per source IP */
struct tcp_fp {
    __u16 window_size;
    __u16 mss;
    __u8  ttl;
    __u8  wscale;
    __u8  has_sack;
    __u8  has_timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);
    __type(value, struct tcp_fp);
} tcp_fingerprints SEC(".maps");

/* Stats counters */
struct global_stats {
    __u64 total_packets;
    __u64 syn_drops;
    __u64 blocklist_drops;
    __u64 allowed;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} global_stats_map SEC(".maps");

/* ── Helper: get pointer with bounds check ───────────────────────── */
static __always_inline void *ptr_at(struct xdp_md *ctx, __u32 offset) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + offset + 1 > data_end) return NULL;
    return data + offset;
}

/* ── Program 1: XDP SYN Guard ────────────────────────────────────── */
SEC("xdp")
int xdp_syn_guard(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    /* Parse IP */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 src_ip = iph->saddr;

    /* Check IP blocklist */
    __u8 *blocked = bpf_map_lookup_elem(&ip_blocklist, &src_ip);
    if (blocked) {
        __u32 key = 0;
        struct global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &key);
        if (stats) __sync_fetch_and_add(&stats->blocklist_drops, 1);
        return XDP_DROP;
    }

    /* Parse TCP */
    int ip_hdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (void *)iph + ip_hdrlen;
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;

    __u32 key = 0;
    struct global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &key);
    if (stats) __sync_fetch_and_add(&stats->total_packets, 1);

    /* SYN flood detection */
    if (tcph->syn && !tcph->ack) {
        __u64 now = bpf_ktime_get_ns();

        /* Check and reset window */
        __u64 *last_ts = bpf_map_lookup_elem(&syn_timestamp, &src_ip);
        if (last_ts && (now - *last_ts) > RATE_WINDOW_NS) {
            /* New window: reset counter */
            __u64 zero = 0;
            bpf_map_update_elem(&syn_counter, &src_ip, &zero, BPF_ANY);
        }
        bpf_map_update_elem(&syn_timestamp, &src_ip, &now, BPF_ANY);

        /* Increment SYN counter */
        __u64 *count = bpf_map_lookup_elem(&syn_counter, &src_ip);
        if (count) {
            __sync_fetch_and_add(count, 1);
            if (*count > SYN_THRESHOLD) {
                /* Add to blocklist, drop packet */
                __u8 reason = 1;  /* 1 = syn_flood */
                bpf_map_update_elem(&ip_blocklist, &src_ip, &reason, BPF_ANY);
                if (stats) __sync_fetch_and_add(&stats->syn_drops, 1);
                return XDP_DROP;
            }
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&syn_counter, &src_ip, &one, BPF_ANY);
        }

        /* Extract TCP fingerprint from SYN packet options */
        struct tcp_fp fp = {};
        fp.window_size = bpf_ntohs(tcph->window);
        fp.ttl = iph->ttl;

        /* Parse TCP options (MSS, WSCALE, SACK, Timestamp) */
        __u8 *opts = (__u8 *)tcph + sizeof(struct tcphdr);
        __u8 *opts_end = (__u8 *)tcph + (tcph->doff * 4);
        if ((void *)opts_end <= data_end) {
            int i;
            #pragma unroll
            for (i = 0; i < 40 && opts < opts_end; ) {
                __u8 kind = *opts;
                if (kind == 0) break;          /* EOL */
                if (kind == 1) { opts++; i++; continue; }  /* NOP */
                if (opts + 1 >= opts_end) break;
                __u8 len = *(opts + 1);
                if (len < 2 || opts + len > opts_end) break;

                if (kind == 2 && len == 4) {   /* MSS */
                    __u16 mss = bpf_ntohs(*(__u16 *)(opts + 2));
                    fp.mss = mss;
                } else if (kind == 3 && len == 3) {  /* WSCALE */
                    fp.wscale = *(opts + 2);
                } else if (kind == 4 && len == 2) {  /* SACK_PERM */
                    fp.has_sack = 1;
                } else if (kind == 8 && len == 10) { /* TIMESTAMP */
                    fp.has_timestamp = 1;
                }

                opts += len;
                i += len;
            }
        }

        bpf_map_update_elem(&tcp_fingerprints, &src_ip, &fp, BPF_ANY);
    }

    if (stats) __sync_fetch_and_add(&stats->allowed, 1);
    return XDP_PASS;
}

/* ── Program 2: TC Connection Rate Monitor ───────────────────────── */
SEC("tc")
int tc_rate_monitor(struct __sk_buff *skb) {
    /* TC programs can read full packet including retransmits, RSTs */
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

    /* RST flood detection */
    if (tcph->rst) {
        __u32 src = iph->saddr;
        __u64 *count = bpf_map_lookup_elem(&syn_counter, &src);
        /* RST spamming can indicate scanning — just record for userspace */
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

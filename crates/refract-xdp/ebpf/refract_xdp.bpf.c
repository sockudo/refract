// XDP hardening program for refract media sockets.
//
// The Rust workspace keeps `#![forbid(unsafe_code)]`; packet memory access in
// eBPF is therefore implemented in verifier-bounded C and loaded by Aya from
// user space.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define REFRACT_CONFIG_LISTEN_PORT 0
#define REFRACT_CONFIG_STUN_RATE 1
#define REFRACT_CONFIG_STUN_BURST 2

#define REFRACT_STAT_PASSED 0
#define REFRACT_STAT_DROPPED_UNSUPPORTED_UDP 1
#define REFRACT_STAT_DROPPED_FRAGMENTED 2
#define REFRACT_STAT_DROPPED_STUN_RATE_LIMITED 3
#define REFRACT_STAT_ACCEPTED_STUN_BINDING 4
#define REFRACT_STAT_ACCEPTED_STUN_OTHER 5
#define REFRACT_STAT_ACCEPTED_DTLS 6
#define REFRACT_STAT_ACCEPTED_SRTP 7
#define REFRACT_STAT_COUNT 8

#define REFRACT_STUN_MAGIC_COOKIE 0x2112a442
#define REFRACT_STUN_BINDING_REQUEST 0x0001
#define REFRACT_STUN_METHOD_MASK 0x3eef
#define REFRACT_NSEC_PER_SEC 1000000000ULL
#define REFRACT_MAX_BUCKETS 1048576

struct refract_ip_key {
    __u8 family;
    __u8 pad[3];
    union {
        __u32 v4;
        __u8 v6[16];
    } addr;
};

struct refract_bucket {
    __u64 last_ns;
    __u32 tokens;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} REFRACT_XDP_CONFIG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, REFRACT_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} REFRACT_XDP_STATS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, REFRACT_MAX_BUCKETS);
    __type(key, struct refract_ip_key);
    __type(value, struct refract_bucket);
} REFRACT_XDP_STUN_BUCKETS SEC(".maps");

static __always_inline void refract_count(__u32 counter)
{
    __u64 *value = bpf_map_lookup_elem(&REFRACT_XDP_STATS, &counter);

    if (value != 0) {
        __sync_fetch_and_add(value, 1);
    }
}

static __always_inline __u64 refract_config(__u32 index, __u64 fallback)
{
    __u64 *value = bpf_map_lookup_elem(&REFRACT_XDP_CONFIG, &index);

    return value == 0 ? fallback : *value;
}

static __always_inline int refract_drop(__u32 counter)
{
    refract_count(counter);
    return XDP_DROP;
}

static __always_inline int refract_pass_counted(__u32 counter)
{
    refract_count(counter);
    refract_count(REFRACT_STAT_PASSED);
    return XDP_PASS;
}

static __always_inline int refract_is_stun_binding(void *payload, void *data_end)
{
    __u8 *bytes = payload;
    __u16 message_type;
    __u32 magic_cookie;

    if (bytes + 20 > (__u8 *)data_end) {
        return 0;
    }

    message_type = bpf_ntohs(*(__u16 *)(bytes));
    magic_cookie = bpf_ntohl(*(__u32 *)(bytes + 4));

    return magic_cookie == REFRACT_STUN_MAGIC_COOKIE &&
           (message_type & REFRACT_STUN_METHOD_MASK) == REFRACT_STUN_BINDING_REQUEST;
}

static __always_inline int refract_is_stun(void *payload, void *data_end)
{
    __u8 *bytes = payload;
    __u32 magic_cookie;

    if (bytes + 20 > (__u8 *)data_end) {
        return 0;
    }

    magic_cookie = bpf_ntohl(*(__u32 *)(bytes + 4));
    return magic_cookie == REFRACT_STUN_MAGIC_COOKIE;
}

static __always_inline int refract_allow_stun_binding(struct refract_ip_key *key)
{
    __u32 rate = (__u32)refract_config(REFRACT_CONFIG_STUN_RATE, 100);
    __u32 burst = (__u32)refract_config(REFRACT_CONFIG_STUN_BURST, 100);
    __u64 now = bpf_ktime_get_ns();
    struct refract_bucket *bucket;
    struct refract_bucket fresh = {};

    if (rate == 0 || burst == 0 || burst < rate) {
        return 0;
    }

    bucket = bpf_map_lookup_elem(&REFRACT_XDP_STUN_BUCKETS, key);
    if (bucket == 0) {
        fresh.last_ns = now;
        fresh.tokens = burst - 1;
        bpf_map_update_elem(&REFRACT_XDP_STUN_BUCKETS, key, &fresh, BPF_ANY);
        return 1;
    }

    if (now > bucket->last_ns) {
        __u64 elapsed = now - bucket->last_ns;
        __u64 refill = elapsed > (~0ULL / rate) ? burst : (elapsed * rate) / REFRACT_NSEC_PER_SEC;

        if (refill > 0) {
            __u64 tokens = bucket->tokens + refill;
            bucket->tokens = tokens > burst ? burst : (__u32)tokens;
            bucket->last_ns = now;
        }
    }

    if (bucket->tokens == 0) {
        return 0;
    }

    bucket->tokens -= 1;
    return 1;
}

static __always_inline int refract_handle_payload(void *payload, void *data_end, struct refract_ip_key *key)
{
    __u8 *bytes = payload;
    __u8 first;

    if (bytes + 1 > (__u8 *)data_end) {
        return refract_drop(REFRACT_STAT_DROPPED_UNSUPPORTED_UDP);
    }

    first = *bytes;

    if (first <= 3 && refract_is_stun(payload, data_end)) {
        if (refract_is_stun_binding(payload, data_end)) {
            if (refract_allow_stun_binding(key) == 0) {
                return refract_drop(REFRACT_STAT_DROPPED_STUN_RATE_LIMITED);
            }
            return refract_pass_counted(REFRACT_STAT_ACCEPTED_STUN_BINDING);
        }
        return refract_pass_counted(REFRACT_STAT_ACCEPTED_STUN_OTHER);
    }

    if (first >= 20 && first <= 63) {
        return refract_pass_counted(REFRACT_STAT_ACCEPTED_DTLS);
    }

    if (first >= 128 && first <= 191) {
        return refract_pass_counted(REFRACT_STAT_ACCEPTED_SRTP);
    }

    return refract_drop(REFRACT_STAT_DROPPED_UNSUPPORTED_UDP);
}

static __always_inline int refract_handle_udp(void *udp, void *data_end, struct refract_ip_key *key)
{
    struct udphdr *udph = udp;
    __u16 listen_port = (__u16)refract_config(REFRACT_CONFIG_LISTEN_PORT, 50000);

    if (udph + 1 > (struct udphdr *)data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(udph->dest) != listen_port) {
        return XDP_PASS;
    }

    return refract_handle_payload(udph + 1, data_end, key);
}

static __always_inline int refract_handle_ipv4(void *ip, void *data_end)
{
    struct iphdr *iph = ip;
    __u16 frag_off;
    __u32 ihl;
    struct refract_ip_key key = {};

    if (iph + 1 > (struct iphdr *)data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    frag_off = bpf_ntohs(iph->frag_off);
    if ((frag_off & (IP_MF | IP_OFFSET)) != 0) {
        return refract_drop(REFRACT_STAT_DROPPED_FRAGMENTED);
    }

    ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph)) {
        return XDP_PASS;
    }

    key.family = AF_INET;
    key.addr.v4 = iph->saddr;
    return refract_handle_udp((__u8 *)ip + ihl, data_end, &key);
}

static __always_inline int refract_ipv6_extension(__u8 next_header)
{
    return next_header == IPPROTO_HOPOPTS ||
           next_header == IPPROTO_ROUTING ||
           next_header == IPPROTO_DSTOPTS;
}

static __always_inline int refract_handle_ipv6(void *ip, void *data_end)
{
    struct ipv6hdr *ip6h = ip;
    __u8 next_header;
    __u64 offset;
    struct refract_ip_key key = {};

    if (ip6h + 1 > (struct ipv6hdr *)data_end) {
        return XDP_PASS;
    }

    next_header = ip6h->nexthdr;
    offset = sizeof(*ip6h);

#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (next_header == IPPROTO_FRAGMENT) {
            return refract_drop(REFRACT_STAT_DROPPED_FRAGMENTED);
        }

        if (!refract_ipv6_extension(next_header)) {
            break;
        }

        __u8 *extension = (__u8 *)ip + offset;
        if (extension + 2 > (__u8 *)data_end) {
            return XDP_PASS;
        }

        next_header = extension[0];
        offset += ((__u64)extension[1] + 1) * 8;
        if ((__u8 *)ip + offset > (__u8 *)data_end) {
            return XDP_PASS;
        }
    }

    if (next_header != IPPROTO_UDP) {
        return XDP_PASS;
    }

    key.family = AF_INET6;
    __builtin_memcpy(key.addr.v6, ip6h->saddr.s6_addr, sizeof(key.addr.v6));
    return refract_handle_udp((__u8 *)ip + offset, data_end, &key);
}

SEC("xdp")
int refract_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u16 ether_type;
    __u64 offset = sizeof(*eth);

    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_PASS;
    }

    ether_type = bpf_ntohs(eth->h_proto);

    if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
        struct vlan_hdr *vlan = data + offset;
        if (vlan + 1 > (struct vlan_hdr *)data_end) {
            return XDP_PASS;
        }
        ether_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        offset += sizeof(*vlan);
    }

    if (ether_type == ETH_P_IP) {
        return refract_handle_ipv4(data + offset, data_end);
    }

    if (ether_type == ETH_P_IPV6) {
        return refract_handle_ipv6(data + offset, data_end);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

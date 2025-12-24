/*
 * XDP DDoS Mitigation Filter - BCC Compatible Version
 * High-performance packet filtering at NIC driver level
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

/* BPF map definitions - BCC style */

/* Flow tracking structure */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u8 flags;
    __u8 pad[7];
};

/* Per-IP tracking structure */
struct ip_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u32 flow_count;
    __u32 syn_count;
    __u32 udp_count;
};

/* Statistics structure (per-CPU) */
struct stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 passed_packets;
    __u64 passed_bytes;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 other_packets;
};

/* BPF Maps - BCC style declarations */
BPF_HASH(flow_map, struct flow_key, struct flow_stats, 65536);
BPF_HASH(ip_tracking_map, __u32, struct ip_stats, 131072);
BPF_HASH(blacklist_map, __u32, __u64, 10000);
BPF_PERCPU_ARRAY(stats_map, struct stats, 1);

/* Helper to get current time */
static __always_inline __u64 get_time_ns(void) {
    return bpf_ktime_get_ns();
}

/* Update per-CPU statistics */
static __always_inline void update_stats(struct stats *s, __u64 bytes, __u8 protocol, int action) {
    if (!s) return;
    
    __sync_fetch_and_add(&s->total_packets, 1);
    __sync_fetch_and_add(&s->total_bytes, bytes);
    
    if (action == XDP_DROP) {
        __sync_fetch_and_add(&s->dropped_packets, 1);
        __sync_fetch_and_add(&s->dropped_bytes, bytes);
    } else if (action == XDP_PASS) {
        __sync_fetch_and_add(&s->passed_packets, 1);
        __sync_fetch_and_add(&s->passed_bytes, bytes);
    }
    
    switch (protocol) {
        case IPPROTO_TCP:
            __sync_fetch_and_add(&s->tcp_packets, 1);
            break;
        case IPPROTO_UDP:
            __sync_fetch_and_add(&s->udp_packets, 1);
            break;
        case IPPROTO_ICMP:
            __sync_fetch_and_add(&s->icmp_packets, 1);
            break;
        default:
            __sync_fetch_and_add(&s->other_packets, 1);
            break;
    }
}

/* Check if IP is blacklisted */
static __always_inline int is_blacklisted(__u32 src_ip) {
    __u64 *timestamp = blacklist_map.lookup(&src_ip);
    return (timestamp != NULL);
}

/* Update IP tracking statistics */
static __always_inline void update_ip_stats(__u32 src_ip, __u64 bytes, __u8 protocol, __u8 tcp_flags) {
    struct ip_stats *ip_stat = ip_tracking_map.lookup(&src_ip);
    
    if (ip_stat) {
        __sync_fetch_and_add(&ip_stat->packets, 1);
        __sync_fetch_and_add(&ip_stat->bytes, bytes);
        ip_stat->last_seen = get_time_ns();
        
        if (protocol == IPPROTO_TCP && (tcp_flags & 0x02)) {
            __sync_fetch_and_add(&ip_stat->syn_count, 1);
        } else if (protocol == IPPROTO_UDP) {
            __sync_fetch_and_add(&ip_stat->udp_count, 1);
        }
    } else {
        struct ip_stats new_stat = {
            .packets = 1,
            .bytes = bytes,
            .last_seen = get_time_ns(),
            .flow_count = 1,
            .syn_count = (protocol == IPPROTO_TCP && (tcp_flags & 0x02)) ? 1 : 0,
            .udp_count = (protocol == IPPROTO_UDP) ? 1 : 0,
        };
        ip_tracking_map.update(&src_ip, &new_stat);
    }
}

/* Update flow statistics */
static __always_inline void update_flow_stats(struct flow_key *key, __u64 bytes, __u8 tcp_flags) {
    struct flow_stats *flow = flow_map.lookup(key);
    
    if (flow) {
        __sync_fetch_and_add(&flow->packets, 1);
        __sync_fetch_and_add(&flow->bytes, bytes);
        flow->last_seen = get_time_ns();
        flow->flags |= tcp_flags;
    } else {
        struct flow_stats new_flow = {
            .packets = 1,
            .bytes = bytes,
            .last_seen = get_time_ns(),
            .flags = tcp_flags,
        };
        flow_map.update(key, &new_flow);
    }
}

/* Main XDP program */
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    
    __u64 packet_size = data_end - data;
    __u32 action = XDP_PASS;
    
    // Get stats structure
    __u32 stats_key = 0;
    struct stats *s = stats_map.lookup(&stats_key);
    
    // Parse Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;
    
    // Only process IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8 protocol = iph->protocol;
    
    // Check blacklist
    if (is_blacklisted(src_ip)) {
        action = XDP_DROP;
        update_stats(s, packet_size, protocol, action);
        return action;
    }
    
    // Parse transport layer and create flow key
    struct flow_key fkey = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .protocol = protocol,
        .src_port = 0,
        .dst_port = 0,
    };
    
    __u8 tcp_flags = 0;
    
    if (protocol == IPPROTO_TCP) {
        tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            goto update_tracking;
        
        fkey.src_port = ntohs(tcph->source);
        fkey.dst_port = ntohs(tcph->dest);
        
        // Extract TCP flags
        tcp_flags = ((unsigned char *)tcph)[13];
        
        // Simple SYN flood detection
        if (tcp_flags & 0x02) {
            struct ip_stats *ip_stat = ip_tracking_map.lookup(&src_ip);
            if (ip_stat && ip_stat->syn_count > 1000) {
                action = XDP_DROP;
            }
        }
        
    } else if (protocol == IPPROTO_UDP) {
        udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            goto update_tracking;
        
        fkey.src_port = ntohs(udph->source);
        fkey.dst_port = ntohs(udph->dest);
    }
    
update_tracking:
    // Update tracking maps
    update_ip_stats(src_ip, packet_size, protocol, tcp_flags);
    update_flow_stats(&fkey, packet_size, tcp_flags);
    update_stats(s, packet_size, protocol, action);
    
    return action;
}

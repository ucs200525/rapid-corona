/*
 * XDP DDoS Mitigation Filter - libbpf Compatible Version
 * High-performance packet filtering at NIC driver level
 * 
 * This file is for standalone compilation with clang/libbpf
 * Use xdp_filter.c for BCC runtime compilation
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Include shared map definitions */
#include "xdp_maps.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

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
    __u64 *timestamp = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    return (timestamp != NULL);
}

/* Update IP tracking statistics */
static __always_inline void update_ip_stats(__u32 src_ip, __u64 bytes, __u8 protocol, __u8 tcp_flags) {
    struct ip_stats *ip_stat = bpf_map_lookup_elem(&ip_tracking_map, &src_ip);
    
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
        bpf_map_update_elem(&ip_tracking_map, &src_ip, &new_stat, BPF_ANY);
    }
}

/* Update flow statistics */
static __always_inline void update_flow_stats(struct flow_key *key, __u64 bytes, __u8 tcp_flags) {
    struct flow_stats *flow = bpf_map_lookup_elem(&flow_map, key);
    
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
        bpf_map_update_elem(&flow_map, key, &new_flow, BPF_ANY);
    }
}

/* Main XDP program */
SEC("xdp")
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
    struct stats *s = bpf_map_lookup_elem(&stats_map, &stats_key);
    
    // Parse Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
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
        
        fkey.src_port = bpf_ntohs(tcph->source);
        fkey.dst_port = bpf_ntohs(tcph->dest);
        
        // Extract TCP flags
        tcp_flags = ((unsigned char *)tcph)[13];
        
        // Simple SYN flood detection
        if (tcp_flags & 0x02) {
            struct ip_stats *ip_stat = bpf_map_lookup_elem(&ip_tracking_map, &src_ip);
            if (ip_stat && ip_stat->syn_count > 1000) {
                action = XDP_DROP;
            }
        }
        
    } else if (protocol == IPPROTO_UDP) {
        udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            goto update_tracking;
        
        fkey.src_port = bpf_ntohs(udph->source);
        fkey.dst_port = bpf_ntohs(udph->dest);
    }
    
update_tracking:
    // Update tracking maps
    update_ip_stats(src_ip, packet_size, protocol, tcp_flags);
    update_flow_stats(&fkey, packet_size, tcp_flags);
    update_stats(s, packet_size, protocol, action);
    
    return action;
}

char _license[] SEC("license") = "GPL";

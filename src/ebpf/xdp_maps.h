/*
 * eBPF Map Definitions for DDoS Mitigation System
 * Shared between kernel XDP program and user-space control plane
 */

#ifndef __XDP_MAPS_H__
#define __XDP_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Maximum values */
#define MAX_FLOWS 65536
#define MAX_IPS 131072
#define MAX_BLACKLIST 10000
#define MAX_CPUS 128

/* Flow tracking structure */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
} __attribute__((packed));

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;  // timestamp in nanoseconds
    __u8 flags;       // TCP flags OR'd together
    __u8 pad[7];
} __attribute__((packed));

/* Per-IP tracking structure */
struct ip_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u32 flow_count;  // Number of flows from this IP
    __u16 syn_count;   // SYN packets (for SYN flood detection)
    __u16 udp_count;   // UDP packets
} __attribute__((packed));

/* Attack signature structure */
struct attack_signature {
    __u32 enabled;
    __u32 signature_type;  // 1=IP, 2=Port, 3=Protocol
    __u32 value;           // IP/Port/Protocol value
    __u64 blocked_packets;
    __u64 blocked_bytes;
} __attribute__((packed));

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
} __attribute__((packed));

/*
 * BPF Maps
 */

/* Flow statistics - LRU hash map for automatic eviction */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_map SEC(".maps");

/* Per-source IP tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);  // Source IP
    __type(value, struct ip_stats);
} ip_tracking_map SEC(".maps");

/* Blacklist - blocked IPs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST);
    __type(key, __u32);  // IP address
    __type(value, __u64);  // Timestamp when blacklisted
} blacklist_map SEC(".maps");

/* Attack signatures */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1000);
    __type(key, __u32);  // Signature ID
    __type(value, struct attack_signature);
} signature_map SEC(".maps");

/* Per-CPU statistics array for lock-free updates */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

/* Configuration map */
struct config {
    __u32 rate_limit_pps;      // Per-IP rate limit (packets/sec)
    __u32 rate_limit_enabled;
    __u32 blacklist_enabled;
    __u32 signature_enabled;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

#endif /* __XDP_MAPS_H__ */

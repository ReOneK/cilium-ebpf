//go:build ignore

#include "common.h"
#include <netinet/in.h>
#include <linux/udp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") start_times = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") rtt_times = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

const struct start_times *unused __attribute__((unused));
const struct rtt_times *unused __attribute__((unused));

SEC("prog")
int handle_packet(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 14);
    if (eth == NULL)
        return 0;

    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = bpf_hdr_pointer(skb, 14 + sizeof(*eth));
    if (ip == NULL)
        return 0;

    if (ip->protocol != IPPROTO_UDP)
        return 0;

    struct udphdr *udp = bpf_hdr_pointer(skb, 14 + sizeof(*eth) + sizeof(*ip));
    if (udp == NULL)
        return 0;

    __u64 ts = bpf_ktime_get_ns();

    __u32 key = udp->source;
    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	__u64 *start_ts = bpf_map_lookup_elem(&start_times, &udp->source);
	if (start_ts == NULL)
        return 0;

    __u64 end_ts = bpf_ktime_get_ns();
    __u64 rtt = end_ts - *start_ts;

    // Store the RTT in the rtt_times map
    bpf_map_update_elem(&rtt_times, &udp->source, &rtt, BPF_ANY);

    return 0;
}
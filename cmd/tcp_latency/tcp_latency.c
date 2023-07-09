//go:build ignore

// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include "linux/ip.h"
// #include <linux/udp.h>
// #include <linux/tcp.h>
// #include <linux/pkt_cls.h>
// #include <linux/ptrace.h>
// #include <linux/utsname.h>
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct latency { 
    u64 ts;
    u64 duration;
};

struct bpf_map_def SEC("maps") start = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct latency),
    .max_entries = 1024,
};

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct latency latency = {};
    latency.ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &latency, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    struct latency *latency;

    if (ret != 0)
        return 0;

    latency = bpf_map_lookup_elem(&start, &pid);
    if (latency != 0) {
        latency->duration = bpf_ktime_get_ns() - latency->ts;
    }
    return 0;
}

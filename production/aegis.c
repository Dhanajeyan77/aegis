//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {
    u32 pid;
    char comm[16];
    char target[256];
    int blocked;
};

// Map to send events to Go Userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Dynamic Policy Map (Key: Target Path, Value: Block Action 1=Block)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, u32);
} blocklist SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct data_t *data;
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = pid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Read the target command path being executed
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&data->target, sizeof(data->target), filename_ptr);
    
    int blocked = 0;
    
    // DYNAMIC MAP LOOKUP
    u32 *action = bpf_map_lookup_elem(&blocklist, &data->target);
    if (action && *action == 1) {
        blocked = 1;
    }

    // Failsafe Static Blocks (just in case)
    if (data->target[0] == '/' && data->target[1] == 'b' && data->target[2] == 'i' && data->target[3] == 'n' && data->target[4] == '/' && data->target[5] == 'r' && data->target[6] == 'm') {
        blocked = 1;
    }
    if (data->target[0] == '/' && data->target[1] == 'u' && data->target[2] == 's' && data->target[3] == 'r' && data->target[4] == '/' && data->target[5] == 'b' && data->target[6] == 'i' && data->target[7] == 'n' && data->target[8] == '/' && data->target[9] == 'r' && data->target[10] == 'm') {
        blocked = 1;
    }

    data->blocked = blocked;
    bpf_ringbuf_submit(data, 0);

    if (blocked) {
        bpf_send_signal(9); // SIGKILL
    }
    
    return 0;
}

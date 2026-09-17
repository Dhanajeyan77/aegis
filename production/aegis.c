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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// We use the raw tracepoint because it's easier to access arguments in CO-RE.
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // Filter out root or self? For now let's just log everything to test Go integration
    struct data_t *data;
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = pid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // ctx->args[0] is the filename pointer
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&data->target, sizeof(data->target), filename_ptr);
    
    int blocked = 0;
    
    // Demo block
    if (data->target[0] == '/' && data->target[1] == 'b' && data->target[2] == 'i' && data->target[3] == 'n' && data->target[4] == '/' && data->target[5] == 'r' && data->target[6] == 'm') {
        blocked = 1;
    }

    data->blocked = blocked;
    bpf_ringbuf_submit(data, 0);

    if (blocked) {
        bpf_send_signal(9);
    }
    
    return 0;
}

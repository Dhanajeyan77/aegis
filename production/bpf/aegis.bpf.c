#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Ringbuffer to send events to the Rust userspace agent
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event_t {
    u32 pid;
    char comm[16];
    char filename[256];
    int blocked;
};

// LSM Hook: bprm_check_security (triggers on execve AFTER data is copied to kernel space)
// This definitively prevents TOCTOU (Time-of-Check to Time-of-Use) attacks.
SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_bprm_check_security, struct linux_binprm *bprm)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event) {
        return 0; // Ringbuffer full
    }

    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Read the file name safely from the kernel structure
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), bprm->filename);

    int blocked = 0;
    
    // Naive suffix check for demo purposes
    int len = 0;
    for (int i = 0; i < 256; i++) {
        if (event->filename[i] == '\0') {
            len = i;
            break;
        }
    }

    if (len >= 2 && event->filename[len-2] == 'r' && event->filename[len-1] == 'm') {
        blocked = 1;
    }

    event->blocked = blocked;
    bpf_ringbuf_submit(event, 0);

    if (blocked) {
        // LSM hooks can reject the action simply by returning a negative error code (e.g., -EPERM)
        // This is much safer and cleaner than bpf_send_signal(SIGKILL).
        return -1; // -EPERM (Permission Denied)
    }

    return 0;
}

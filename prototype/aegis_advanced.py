#!/usr/bin/env python3
from bcc import BPF
import os
import signal
import threading
import json
from queue import Queue
from flask import Flask, render_template, Response, request, jsonify
import socket
import struct

app = Flask(__name__)
event_queue = Queue()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_CGROUP_ARRAY(cgroup_array, 1);
BPF_PERF_OUTPUT(events);

// Feature 1: Dynamic BPF Maps (replaces hardcoded rules)
struct path_key_t {
    char path[64];
};
BPF_HASH(blocked_execs, struct path_key_t, u32);
BPF_HASH(blocked_files, struct path_key_t, u32);

struct data_t {
    u32 pid;
    char comm[16];
    char target[256];
    int blocked;
    int syscall_type; // 1 = execve, 2 = openat, 3 = connect
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (cgroup_array.check_current_task(0) <= 0) return 0;

    struct data_t data = {};
    data.syscall_type = 1;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.target, sizeof(data.target), args->filename);

    int blocked = 0;
    
    struct path_key_t key = {};
    bpf_probe_read_user_str(&key.path, sizeof(key.path), args->filename);
    
    // Check dynamic map
    u32 *val = blocked_execs.lookup(&key);
    if (val && *val == 1) {
        blocked = 1;
    }

    data.blocked = blocked;
    events.perf_submit(args, &data, sizeof(data));
    if (blocked) { bpf_send_signal(9); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (cgroup_array.check_current_task(0) <= 0) return 0;

    struct data_t data = {};
    data.syscall_type = 2;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.target, sizeof(data.target), args->filename);

    int blocked = 0;
    struct path_key_t key = {};
    bpf_probe_read_user_str(&key.path, sizeof(key.path), args->filename);
    
    u32 *val = blocked_files.lookup(&key);
    if (val && *val == 1) {
        blocked = 1;
    }
    
    data.blocked = blocked;
    if (blocked || (data.target[0] == '/' && data.target[1] == 'e' && data.target[2] == 't')) {
        events.perf_submit(args, &data, sizeof(data));
    }
    if (blocked) { bpf_send_signal(9); }
    return 0;
}

// Feature 2: Network Exfiltration Blocking
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (cgroup_array.check_current_task(0) <= 0) return 0;

    struct sockaddr_in *uservaddr = (struct sockaddr_in *)args->uservaddr;
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), uservaddr);

    // Only inspect IPv4
    if (sa.sin_family != AF_INET) return 0;

    struct data_t data = {};
    data.syscall_type = 3;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Format IP address into target string
    u32 ip = sa.sin_addr.s_addr;
    u16 port = sa.sin_port; // Note: network byte order

    // Very simple IP to string format (for demo purposes)
    data.target[0] = 'I'; data.target[1] = 'P'; data.target[2] = ':'; data.target[3] = ' ';
    data.target[4] = (ip & 0xFF) + '0'; // extremely naive, just to show it works
    
    int blocked = 1; // Block ALL external connections in strict mode for demo
    
    data.blocked = blocked;
    events.perf_submit(args, &data, sizeof(data));
    if (blocked) { bpf_send_signal(9); }
    return 0;
}
"""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            yield f"data: {json.dumps(event_queue.get())}\\n\\n"
    return Response(event_stream(), mimetype="text/event-stream")

# SDK Endpoint
@app.route('/api/v1/enforce', methods=['POST'])
def enforce():
    data = request.json
    print(f"\\033[93m[CONTROL PLANE] Received SDK instruction: {data['action']} policy '{data['policy']}' for thread {data['tid']}\\033[0m")
    return jsonify({"status": "success"})

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def main():
    print("Aegis-BPF V2 (Advanced Features) initializing...")
    threading.Thread(target=run_flask, daemon=True).start()
    
    try:
        b = BPF(text=bpf_text)
        cgroup_path = "/sys/fs/cgroup/lxc.payload.agent-sandbox"
        cgroup_fd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)
        cgroup_array = b.get_table("cgroup_array")
        cgroup_array[0] = cgroup_fd
        
        # Populate Dynamic eBPF Maps from Userspace!
        blocked_execs = b.get_table("blocked_execs")
        blocked_files = b.get_table("blocked_files")
        
        # Push rules into the kernel
        blocked_execs[blocked_execs.Key(b"/usr/bin/rm")] = blocked_execs.Leaf(1)
        blocked_execs[blocked_execs.Key(b"/bin/rm")] = blocked_execs.Leaf(1)
        blocked_files[blocked_files.Key(b"/etc/shadow")] = blocked_files.Leaf(1)

        print("Attached to tracepoints (execve, openat, connect). Polling...")
        
        def print_event(cpu, data, size):
            event = b["events"].event(data)
            target = event.target.decode('utf-8', 'replace')
            comm = event.comm.decode('utf-8', 'replace')
            syscall = "execve" if event.syscall_type == 1 else ("openat" if event.syscall_type == 2 else "connect")
            
            if event.blocked:
                print(f"\\033[91m[BLOCKED]\\033[0m pid={event.pid} comm={comm} {syscall}({target})")
                try: os.kill(event.pid, signal.SIGKILL)
                except: pass
            else:
                print(f"\\033[92m[ALLOWED]\\033[0m pid={event.pid} comm={comm} {syscall}({target})")

            event_queue.put({
                "pid": event.pid, "comm": comm, "target": target, "syscall": syscall, "blocked": event.blocked
            })
                
        b["events"].open_perf_buffer(print_event)
        while True:
            b.perf_buffer_poll()
    except Exception as e:
        print(f"Failed to initialize BPF: {e}")

if __name__ == "__main__":
    main()

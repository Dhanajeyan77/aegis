#!/usr/bin/env python3
from bcc import BPF
import os
import signal
import threading
import json
import time
from queue import Queue
from flask import Flask, render_template, Response

# Flask App Setup
app = Flask(__name__)
event_queue = Queue()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_CGROUP_ARRAY(cgroup_array, 1);
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char target[256];
    int blocked;
    int syscall_type; // 1 = execve, 2 = openat, 3 = connect
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (cgroup_array.check_current_task(0) <= 0) {
        return 0;
    }

    struct data_t data = {};
    data.syscall_type = 1;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.target, sizeof(data.target), args->filename);

    int blocked = 0;
    char t[256];
    __builtin_memcpy(&t, data.target, sizeof(t));

    if (t[0] == '/' && t[1] == 'b' && t[2] == 'i' && t[3] == 'n' && t[4] == '/' && t[5] == 'r' && t[6] == 'm') blocked = 1;
    else if (t[0] == '/' && t[1] == 'u' && t[2] == 's' && t[3] == 'r' && t[4] == '/' && t[5] == 'b' && t[6] == 'i' && t[7] == 'n' && t[8] == '/' && t[9] == 'r' && t[10] == 'm') blocked = 1;
    else if (t[0] == 'r' && t[1] == 'm') blocked = 1;
    
    data.blocked = blocked;
    events.perf_submit(args, &data, sizeof(data));
    if (blocked) { bpf_send_signal(9); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (cgroup_array.check_current_task(0) <= 0) {
        return 0;
    }

    struct data_t data = {};
    data.syscall_type = 2;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.target, sizeof(data.target), args->filename);

    int blocked = 0;
    char t[256];
    __builtin_memcpy(&t, data.target, sizeof(t));

    if (t[0] == '/' && t[1] == 'e' && t[2] == 't' && t[3] == 'c' && t[4] == '/' && t[5] == 's' && t[6] == 'h' && t[7] == 'a' && t[8] == 'd' && t[9] == 'o' && t[10] == 'w') {
        blocked = 1;
    }
    
    data.blocked = blocked;
    if (blocked || (t[0] == '/' && t[1] == 't' && t[2] == 'm' && t[3] == 'p')) {
        events.perf_submit(args, &data, sizeof(data));
    }
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
            # We pop events from the queue and send to the frontend
            event_data = event_queue.get()
            yield f"data: {json.dumps(event_data)}\\n\\n"
    return Response(event_stream(), mimetype="text/event-stream")

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def main():
    print("Aegis-BPF policy engine with Web UI initializing...")
    
    # Start Flask in a background thread
    threading.Thread(target=run_flask, daemon=True).start()
    print("Web Dashboard running at http://0.0.0.0:5000")

    try:
        b = BPF(text=bpf_text)
        
        cgroup_path = "/sys/fs/cgroup/lxc.payload.agent-sandbox"
        if not os.path.exists(cgroup_path):
            print(f"Error: cgroup path {cgroup_path} not found.")
            exit(1)
            
        cgroup_fd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)
        cgroup_array = b.get_table("cgroup_array")
        cgroup_array[0] = cgroup_fd
        
        print("Attached to tracepoints (execve, openat). Polling for events...")
        
        def print_event(cpu, data, size):
            event = b["events"].event(data)
            target = event.target.decode('utf-8', 'replace')
            comm = event.comm.decode('utf-8', 'replace')
            syscall = "execve" if event.syscall_type == 1 else ("openat" if event.syscall_type == 2 else "connect")
            
            # Print to terminal
            if event.blocked:
                print(f"\\033[91m[BLOCKED]\\033[0m pid={event.pid} comm={comm} {syscall}({target})")
                try: os.kill(event.pid, signal.SIGKILL)
                except: pass
            else:
                print(f"\\033[92m[ALLOWED]\\033[0m pid={event.pid} comm={comm} {syscall}({target})")

            # Push to web UI
            event_queue.put({
                "pid": event.pid,
                "comm": comm,
                "target": target,
                "syscall": syscall,
                "blocked": event.blocked
            })
                
        b["events"].open_perf_buffer(print_event)
        
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\\nShutting down Aegis-BPF.")
                exit()
    except Exception as e:
        print(f"Failed to initialize BPF: {e}")

if __name__ == "__main__":
    main()

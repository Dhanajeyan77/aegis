# Aegis-BPF: Kernel-Level Runtime Containment for AI Agents

AI agents are increasingly given real power: the ability to run commands, read/write files, and browse the internet. But what happens when an AI suffers a prompt injection, or hallucinates and decides to delete a database? 

Current solutions fail because they either try to filter the AI's prompts (which attackers constantly bypass), or they isolate the AI in a container (which doesn't stop the AI from misusing the legitimate access it was given *inside* that container).

**Aegis-BPF controls what a corrupted AI agent is physically capable of doing—enforced at the operating system kernel level using eBPF.**

## Why not just use Falco or Cilium (Tetragon)?
Falco and Cilium are incredible tools, but they are built for **Generic Cloud Security** (catching human hackers and malware). 
1. **The Context Gap:** Falco sees `python3` modifying a file. It doesn't know if a human user authorized the AI to modify that file, or if the AI went rogue. If you use Falco on an AI agent, you will drown in false positives.
2. **Purpose-Built Enforcement:** Aegis-BPF is built specifically for the Agentic AI execution loop. The AI Framework dynamically registers the agent's *approved execution context* with the Aegis Control Plane. When the AI attempts a syscall outside of its strictly authorized intent, the Aegis eBPF LSM hook intercepts the syscall and instantly terminates the execution.

## 🚀 Product Roadmap & Future Features

We are actively building the next generation of AI runtime security:

1. **Dynamic eBPF Maps (Implemented in V2):** Hardcoded policies have been replaced with high-speed eBPF Hash Maps, allowing the Control Plane to push new allow/deny rules into the Linux kernel in milliseconds without recompiling.
2. **Network Exfiltration Blocking (`connect` enforcement):** Prevents AI agents from sending sensitive data to unauthorized external servers by hooking outbound network sockets.
3. **Python AI SDK (Context-Aware Enforcement):** A native Python SDK (`aegis.enforce()`) that allows AI developers (using LangChain, Autogen, etc.) to wrap specific agent tasks in granular, kernel-enforced sandboxes tied directly to the thread's PID.
4. **LLM-to-BPF Policy Translation:** Developers will write plain English intent ("Allow the AI to read /var/log and hit the Stripe API"). Aegis will use an LLM to automatically translate that intent into strict, low-level eBPF syscall rules.

## Repository Structure

### 1. `/prototype` (The Hackathon MVP)
Contains the fully functional, live-demo version of Aegis-BPF.
*   **eBPF Engine:** Python/BCC script injecting eBPF C code into kernel tracepoints (`execve`, `openat`, `connect`).
*   **Web Control Plane:** A Flask web server streaming real-time Server-Sent Events to a React/Tailwind dashboard.
*   **AI SDK & Agent:** A simulated LangChain-style agent wrapped in the `Aegis SDK` that triggers malicious actions during a prompt injection.

### 2. `/production` (The Enterprise Architecture)
Contains the foundation for the shippable enterprise product.
*   **`/bpf`**: Uses advanced **eBPF LSM (Linux Security Modules)** hooks (`bpf_lsm_bprm_check_security`). This completely eliminates TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities.
*   **`/agent`**: A **Rust-based** node agent (using `Aya`) for zero garbage-collection overhead in MicroVMs (e.g., AWS Firecracker).
*   **`/control-plane`**: A **Golang-based** API Server. Go is the native language of Kubernetes, allowing this control plane to scale as a K8s Operator.
*   **`/packaging`**: Uses nFPM to compile agents into standard `.deb` and `.rpm` packages.

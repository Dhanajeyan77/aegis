# Aegis-BPF: Kernel-Level Runtime Containment for AI Agents

AI agents are increasingly given real power: the ability to run commands, read/write files, and browse the internet. But what happens when an AI suffers a prompt injection, or hallucinates and decides to delete a database? 

Current solutions fail because they either try to filter the AI's prompts (which attackers constantly bypass), or they isolate the AI in a container (which doesn't stop the AI from misusing the legitimate access it was given *inside* that container).

**Aegis-BPF controls what a corrupted AI agent is physically capable of doing—enforced at the operating system kernel level using eBPF.**

## Why not just use Falco or Cilium (Tetragon)?
This is the most common question. Falco and Cilium are incredible tools, but they are built for **Generic Cloud Security** (catching human hackers and malware). 
1. **The Context Gap:** Falco sees `python3` modifying a file. It doesn't know if a human user authorized the AI to modify that file, or if the AI went rogue. If you use Falco on an AI agent, you will either block the AI from doing its job, or drown in false positives.
2. **Purpose-Built Enforcement:** Aegis-BPF is built specifically for the Agentic AI execution loop. In our production architecture, the AI Framework dynamically registers the agent's *approved execution context* with the Aegis Control Plane. When the AI attempts a syscall outside of its strictly authorized intent (e.g., trying to read `/etc/shadow` during a web-scraping task), the Aegis eBPF LSM hook intercepts the syscall and instantly terminates the execution.

Aegis bridges the gap between the AI's application-level intent and the kernel's execution reality.

## Repository Structure

### 1. `/prototype` (The Hackathon MVP)
Contains the fully functional, live-demo version of Aegis-BPF.
*   **eBPF Engine:** A Python/BCC script that compiles eBPF C code and injects it into the kernel tracepoints (`execve`, `openat`).
*   **Web Control Plane:** A Flask web server streaming real-time Server-Sent Events to a dark-mode React/Tailwind dashboard.
*   **Toy AI Agent:** A simulated agent inside an unprivileged LXC container that executes normal commands, and attempts malicious commands when triggered by a prompt injection.

### 2. `/production` (The Enterprise Architecture)
Contains the foundation for the shippable enterprise product.
*   **`/bpf`**: Uses advanced **eBPF LSM (Linux Security Modules)** hooks (`bpf_lsm_bprm_check_security`). This completely eliminates TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities present in standard tracepoints.
*   **`/agent`**: A **Rust-based** node agent (using the `Aya` framework). Rust provides zero garbage-collection overhead and absolute memory safety, making it the perfect language for monitoring highly constrained MicroVMs (like AWS Firecracker).
*   **`/control-plane`**: A **Golang-based** API Server. Go is the native language of Kubernetes, allowing this control plane to scale as a K8s Operator, managing policies across thousands of AI pods.
*   **`/packaging`**: Uses nFPM to instantly compile the agents into standard `.deb` and `.rpm` packages running as highly-privileged `systemd` services.

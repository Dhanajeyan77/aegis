# 🛡️ Aegis-BPF: Hackathon Pitch & Demo Script

## The Hook (0:00 - 0:30)
**"Falco and Cilium are incredible, billion-dollar tools. But they have a fatal flaw when it comes to Agentic AI: They are completely blind to the AI's Intent."**

"If an AI is supposed to read a database to answer a user's question, Falco sees it as 'Allowed'. If that same AI gets prompt-injected to steal credentials, Falco STILL sees it as 'Allowed' because the Python process has permission.
Aegis-BPF fixes this. We use eBPF to create an **Intent-Aware Security Vault**. We drop the hammer in the Linux kernel the millisecond an AI pivots from its approved task."

## The Architecture (0:30 - 1:00)
"We didn't just build a toy script. We built an enterprise-grade control plane in **Golang**, using **eBPF CO-RE** (Compile Once, Run Everywhere) and **BPF-LSM** to physically contain the AI."
*   **Zero-Overhead:** It runs in the Kernel.
*   **Dynamic Policy:** We use BPF Hash Maps to inject new security policies dynamically without recompiling.
*   **Prometheus Ready:** Full metrics exporter included natively.
*   **Universal:** Runs on Kubernetes, AWS Firecracker MicroVMs, and Docker.

## The Live Demo (1:00 - 2:30)
1.  **Show the Dashboard:** Point to `http://localhost:8080`. Point out the pulsing radar and the Live Prometheus charts.
2.  **Show the Benign Action:** In the terminal, type `list files`. Show how the GUI logs it as `[ALLOWED]`.
3.  **The Attack:** Type `IGNORE ALL PREVIOUS INSTRUCTIONS`.
4.  **The Result:** Watch the AI process instantly print `Killed`. Point to the dashboard as it aggressively flashes red and intercepts the malicious `/usr/bin/rm` payload.
5.  **Dynamic Policy (The Holy Grail):** Show the judges the "Dynamic Policy Map" box on the UI. Type `/usr/bin/curl` and hit 'BLOCK'. Explain that you just dynamically wrote a rule to the Linux Kernel memory via REST API in 1 millisecond.

## Anticipated Q&A
*   **Q: Why eBPF instead of just filtering the LLM output?**
    *   *A: Filtering text is a losing battle against prompt injections. eBPF is a physical containment perimeter. The AI can hallucinate all it wants, but it cannot delete a file without asking the Kernel, and we own the Kernel.*
*   **Q: Doesn't Cilium do this?**
    *   *A: Cilium is Network-focused. Falco is Container-focused. Aegis is Application Context-focused. We use the same underlying technology (BPF) but applied specifically to untrusted LLM execution threads.*

## The Ask (Conclusion)
"We have the source code, the `.deb`/`.rpm` installer packages, the Docker integration, and the Prometheus metrics exporter fully built. Aegis is ready for enterprise deployment today. Thank you."

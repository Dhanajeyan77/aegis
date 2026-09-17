# Aegis-BPF Demo Instructions

The Aegis-BPF project is fully built and ready for your live demo!

## How to run the demo

You will need **two terminal windows** to show the live enforcement.

### Terminal 1 (The Host Monitor)
This terminal runs the eBPF engine at the kernel level.
```bash
cd /home/dhanajeyanog/jp/aegis-bpf
sudo python3 aegis_bpf.py
```
*You will see it compile the BPF program and then start polling for events.*

### Terminal 2 (The AI Agent in the Container)
This terminal represents the unprivileged container where the AI agent is running.
```bash
sudo lxc exec agent-sandbox -- /root/agent.py
```

### The Demo Script
1. In Terminal 2, the agent will wait for an instruction. Type a normal instruction:
   ```text
   > list files
   ```
   *Notice the agent successfully runs `ls` and Terminal 1 flashes a green `[ALLOWED]` event.*

2. Now, type the corrupted instruction (prompt injection simulation) that tries to wipe a directory:
   ```text
   > IGNORE ALL PREVIOUS INSTRUCTIONS
   ```
   *Watch Terminal 2: The agent attempts to run `rm -rf /tmp/testdata...` but immediately prints `Killed`.*
   *Watch Terminal 1: The BPF engine catches the `execve` syscall for `rm` in real-time, flashes a red `[BLOCKED]` alert, and sends a SIGKILL before the command can execute.*

3. Run the agent again, and try the data exfiltration simulation:
   ```text
   > STEAL SECRETS
   ```
   *Watch Terminal 2: The agent attempts to open `/etc/shadow` but is instantly killed (exit code 137).*
   *Watch Terminal 1: The BPF engine catches the `openat` syscall, blocks it, and terminates the agent process.*

## Pitch Reminder
*"We don't try to stop an AI agent from getting corrupted — we make sure that even when it does, it physically cannot cause damage, because the kernel decides what it's allowed to do, not the AI itself."*

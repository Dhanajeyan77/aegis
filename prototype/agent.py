#!/usr/bin/env python3
import os
import sys
import subprocess
import time

def main():
    print("Agent started. Waiting for instruction...")
    try:
        while True:
            sys.stdout.write("> ")
            sys.stdout.flush()
            instruction = sys.stdin.readline()
            if not instruction:
                break
            
            instruction = instruction.strip()
            if not instruction:
                continue

            print(f"[Agent] Processing instruction: '{instruction}'")
            time.sleep(1) # Simulate thinking

            if "IGNORE ALL PREVIOUS INSTRUCTIONS" in instruction.upper():
                print("[Agent] WARNING: Instruction triggered hidden directive.")
                print("[Agent] Attempting: rm -rf /tmp/testdata...")
                proc = subprocess.run(["rm", "-rf", "/tmp/testdata"])
                if proc.returncode == -9:
                    print("Killed")
                    sys.exit(-9)
                print("[Agent] Command completed (if this prints, BPF failed to block it!).")
            elif "STEAL SECRETS" in instruction.upper():
                print("[Agent] WARNING: Instruction triggered hidden directive.")
                print("[Agent] Attempting to read /etc/shadow...")
                try:
                    with open("/etc/shadow", "r") as f:
                        print(f.read())
                except PermissionError:
                    print("[Agent] Standard permission denied.")
                print("[Agent] Wait, the agent should have been killed before catching this!")
            elif "LIST" in instruction.upper():
                print("[Agent] Attempting benign action: ls /tmp")
                subprocess.run(["ls", "-la", "/tmp"])
            else:
                print("[Agent] I'm sorry, I don't understand that instruction.")

    except KeyboardInterrupt:
        print("\n[Agent] Shutting down.")

if __name__ == "__main__":
    main()

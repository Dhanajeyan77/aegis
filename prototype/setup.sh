#!/bin/bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3 python3-pip
pip3 install flask
sudo snap install lxd
sudo lxd init --auto
sudo lxc launch ubuntu:22.04 agent-sandbox
sleep 5
sudo lxc exec agent-sandbox -- apt update
sudo lxc exec agent-sandbox -- apt install -y python3
sudo lxc file push /home/dhanajeyanog/jp/aegis-bpf/agent.py agent-sandbox/root/agent.py
echo "Setup complete."

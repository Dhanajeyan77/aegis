package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.11.0 bpf aegis.c -- -I/usr/include/bpf

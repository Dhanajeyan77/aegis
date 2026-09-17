package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"strings"
	_ "embed"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed index.html
var indexHTML []byte

type Event struct {
	PID     uint32
	Comm    [16]byte
	Target  [256]byte
	Blocked int32
}

type UIEvent struct {
	PID     uint32 `json:"pid"`
	Comm    string `json:"comm"`
	Target  string `json:"target"`
	Syscall string `json:"syscall"`
	Blocked int    `json:"blocked"`
}

type PolicyRequest struct {
	Path   string `json:"path"`
	Action string `json:"action"` 
}

var eventChan = make(chan UIEvent, 100)
var clients = make(map[chan UIEvent]bool)
var blocklistMap *ebpf.Map

// PROMETHEUS METRICS
var (
	eventsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegis_syscalls_total",
		Help: "The total number of syscalls processed by the eBPF hook",
	})
	threatsBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegis_threats_blocked_total",
		Help: "The total number of malicious AI actions blocked in the kernel",
	})
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write(indexHTML)
}

func sseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan := make(chan UIEvent, 10)
	clients[clientChan] = true

	defer func() {
		delete(clients, clientChan)
		close(clientChan)
	}()

	flusher, _ := w.(http.Flusher)

	for event := range clientChan {
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
}

func apiPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var key [256]byte
	copy(key[:], req.Path)

	var value uint32 = 0
	if req.Action == "block" {
		value = 1
	}
	if err := blocklistMap.Put(key, value); err != nil {
		http.Error(w, "Failed to update kernel map", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\": \"success\", \"message\": \"Kernel policy updated for %s\"}", req.Path)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}
	log.Println("Aegis-BPF Enterprise Node Engine initializing...")

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()
	
	blocklistMap = objs.Blocklist

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()
	log.Println("Kernel eBPF hooks attached successfully.")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	go func() {
		http.HandleFunc("/", handler)
		http.HandleFunc("/stream", sseHandler)
		http.HandleFunc("/api/policy", apiPolicyHandler)
		http.Handle("/metrics", promhttp.Handler()) // PROMETHEUS METRICS ENDPOINT
		log.Println("Web Dashboard running on http://0.0.0.0:8080")
		log.Println("Prometheus Metrics on http://0.0.0.0:8080/metrics")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		for event := range eventChan {
			for client := range clients {
				client <- event
			}
		}
	}()

	go func() {
		var bpfEvent Event
		for {
			record, err := rd.Read()
			if err != nil {
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err == nil {
				comm := string(bytes.TrimRight(bpfEvent.Comm[:], "\x00"))
				target := string(bytes.TrimRight(bpfEvent.Target[:], "\x00"))

				if strings.Contains(comm, "snapd") || strings.Contains(comm, "systemd") || strings.Contains(comm, "cron") || strings.Contains(comm, "dbus") || strings.Contains(comm, "apparmor") {
					continue
				}

				eventsProcessed.Inc()

				uiEvent := UIEvent{
					PID:     bpfEvent.PID,
					Comm:    comm,
					Target:  target,
					Syscall: "execve",
					Blocked: int(bpfEvent.Blocked),
				}
				
				if bpfEvent.Blocked == 1 {
					threatsBlocked.Inc()
					log.Printf("\033[91m[BLOCKED]\033[0m PID: %d, Comm: %s, Exec: %s", bpfEvent.PID, comm, target)
				}
				
				eventChan <- uiEvent
			}
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Shutting down Aegis Node...")
}

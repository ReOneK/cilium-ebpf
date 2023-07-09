package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type latency bpf tcp_latency.c -- -I../headers

func main() {
	spec, err := ebpf.LoadCollection("tcp_latency.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}

	prog := spec.Programs["kprobe/tcp_v4_connect"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Program not found\n")
		os.Exit(1)
	}

	kp, err := link.Kprobe("tcp_v4_connect", prog, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe: %v\n", err)
		os.Exit(1)
	}
	defer kp.Close()

	mapVal := spec.Maps["start"]
	if mapVal == nil {
		fmt.Fprintf(os.Stderr, "Map not found\n")
		os.Exit(1)
	}

	for {
		var key, nextKey uint32
		for {
			var latency Latency
			err := mapVal.LookupAndDelete(&key, &latency)
			if err != nil {
				break
			}

			fmt.Printf("PID %v: %v\n", key, time.Duration(latency.Duration)*time.Nanosecond)
			key = nextKey
		}

		time.Sleep(time.Second)
	}
}

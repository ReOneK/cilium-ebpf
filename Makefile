CLANG ?= clang
CFLAGS := -O2 -g -Wall

build: 
	cd cmd/tcplatency && \
	go build -o ../../bin/tcplatency .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

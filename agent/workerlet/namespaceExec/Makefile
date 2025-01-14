.PHONY: all namespace_exec

# Default target: build the namespace_exec binary
all: namespace_exec

# Build namespace_exec from namespace_exec.go
namespace_exec:
	go build -ldflags='-s -w' -buildvcs=false -o namespace_exec namespace_exec.go

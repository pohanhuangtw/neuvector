package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func chroot(root string) (bool, error) {
	if err := unix.Chroot(root); err != nil {
		return false, fmt.Errorf("chrooting to directory %q: %w", root, err)
	}
	return true, nil
}

func main() {
	var pid int
	flag.IntVar(&pid, "p", 0, "target pid")
	flag.Parse()

	targetRoot := fmt.Sprintf("/proc/%d/root", pid)

	if _, err := os.Stat(targetRoot); os.IsNotExist(err) {
		fmt.Printf("target root path does not exist: %s\n", targetRoot)
		panic(err)
	}

	canChroot, err := chroot(targetRoot)
	if err != nil {
		fmt.Printf("chroot failed: %v\n", err)
		panic(err)
	}
	if !canChroot {
		fmt.Printf("chroot failed\n")
		panic("chroot failed")
	}

	cmd := exec.Command("./trivy", "fs", "--format", "cyclonedx", "/") // . 代表當前目錄

	cmd.Env = append(os.Environ(), "TMPDIR=.")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("trivy fs: %v\n", err)
	}

	fmt.Println("stdout:", stdout.String())
}

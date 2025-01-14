package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// fsExecve uses execveat(2) on a memfd to replace our process with the given binary.
func fsExecve(fd uintptr, argv []string, envv []string) error {
	pathnamep, err := unix.BytePtrFromString("")
	if err != nil {
		return err
	}

	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}

	envvp, err := syscall.SlicePtrFromStrings(envv)
	if err != nil {
		return err
	}

	_, _, errno := unix.RawSyscall6(
		unix.SYS_EXECVEAT,
		fd,
		uintptr(unsafe.Pointer(pathnamep)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])),
		uintptr(unix.AT_EMPTY_PATH),
		0,
	)

	if errno != 0 {
		return errno
	}
	return nil
}

// namespaceAwareExec executes a binary in the mount namespace of a target process.
// It takes a binary path (-b flag) and target process ID (-p flag) as required arguments.
// The binary is loaded into memory and executed via memfd to avoid filesystem dependencies.
// Any additional arguments after the flags are passed to the executed binary.
func namespaceAwareExec() error {
	binaryPath := flag.String("b", "", "binary path (Required)")
	nsPath := flag.String("p", "", "ns path of pid of the target namespace (Required)")
	namespace := flag.String("n", "", "namespace to use (Required)")
	flag.Parse()

	if *binaryPath == "" {
		err := errors.New("must specify a binary path via -b")
		log.Fatal(err)
		return err
	}

	if *nsPath == "" {
		err := errors.New("must specify a ns path via -p")
		log.Fatal(err)
		return err
	}

	if *namespace == "" {
		err := errors.New("must specify a namespace via -n")
		log.Fatal(err)
		return err
	}

	// Remaining arguments after -b, -p
	remainingArgs := flag.Args()
	args := append([]string{*binaryPath}, remainingArgs...)

	// Need to stay on the same thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		err = os.NewSyscallError("unshare(CLONE_FS)", err)
		log.Fatalf("unshare(CLONE_FS) failed: %v", err)
		return err
	}

	// Read the binary into memory
	bin, err := os.ReadFile(*binaryPath)
	if err != nil {
		log.Fatalf("Failed to read binary (%s): %v", *binaryPath, err)
		return err
	}

	// Create memfd for the binary
	fd, err := unix.MemfdCreate("fdexe", unix.MFD_CLOEXEC)
	if err != nil {
		log.Fatalf("MemfdCreate failed: %v", err)
		return err
	}
	defer unix.Close(fd)

	// Write the binary data to the memfd
	if _, err := unix.Write(fd, bin); err != nil {
		log.Fatalf("Writing to memfd failed: %v", err)
		return err
	}

	// Open the target mount namespace
	namespaceFilePath := filepath.Join(*nsPath, *namespace)
	nsFd, err := os.Open(namespaceFilePath)
	if err != nil {
		log.Fatalf("Failed to open namespace: %v", err)
		return err
	}
	defer nsFd.Close()

	// Setns to that target namespace
	if err := unix.Setns(int(nsFd.Fd()), unix.CLONE_NEWNS); err != nil {
		log.Fatalf("Failed to set namespace: %v", err)
		return err
	}

	// Exec via memfd (execveat)
	if err := fsExecve(uintptr(fd), args, os.Environ()); err != nil {
		log.Fatalf("Fexecve failed: %v", err)
		return err
	}

	return nil
}

func main() {
	if err := namespaceAwareExec(); err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

package proctest

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// cmdlineTimeout is how long Open waits for a process's command line to
// show its marker.
const cmdlineTimeout = 2 * time.Second

// Process is a process held by a pidfd, which keeps naming that process even
// after it is gone and its ID reused.
type Process struct {
	fd int
}

// Open opens a pidfd for pid and makes sure it is the process under test:
// its command line must contain marker. Call it while the process is
// known to be alive, for instance while it waits for Ack.
func Open(t *testing.T, pid int, marker string) *Process {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatalf("pidfd for process %d: %v", pid, err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	p := &Process{fd: fd}
	// The command line is read through the ID, which names the pidfd's
	// process for as long as that is alive, so check that it still is. A
	// process in the middle of exec (a background job of a shell, just
	// started) has an empty command line until the new program is in place,
	// so wait for it.
	var cmdline []byte
	deadline := time.Now().Add(cmdlineTimeout)
	for {
		var err error
		cmdline, err = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil || !p.Alive() {
			t.Fatalf("process %d was gone before the test could watch it", pid)
		}
		if strings.Contains(string(cmdline), marker) || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !strings.Contains(string(cmdline), marker) {
		t.Fatalf("process %d is not the process under test: %q", pid, cmdline)
	}
	return p
}

// Alive reports whether the process still exists, as a zombie included:
// only once it is reaped is it gone.
func (p *Process) Alive() bool {
	err := unix.PidfdSendSignal(p.fd, 0, nil, 0)
	return !errors.Is(err, unix.ESRCH)
}

// Kill sends SIGKILL to the process, if it is still the one opened.
func (p *Process) Kill() {
	_ = unix.PidfdSendSignal(p.fd, unix.SIGKILL, nil, 0)
}

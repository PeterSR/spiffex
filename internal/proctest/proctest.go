// Package proctest lets tests watch and kill processes they did not start
// themselves, such as what a verifier leaves behind, without signalling a
// process ID that may meanwhile belong to someone else.
package proctest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WaitForPID waits for path to hold a process ID greater than 1, as a
// process under test writes it, and returns it.
func WaitForPID(t *testing.T, path string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil && strings.HasSuffix(string(data), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			// Signalling 0 or -1 would reach this process's group, or every
			// process the user owns.
			if err != nil || pid <= 1 {
				t.Fatalf("%s: not a process ID: %q", filepath.Base(path), data)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("no process ID in %s after %s", path, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Ack creates the file a process under test waits for before it goes on,
// once the test has opened it.
func Ack(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// WaitGone waits until p has exited and been reaped. If it is still there
// at the timeout, it is killed and the test fails.
func (p *Process) WaitGone(t *testing.T, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for p.Alive() {
		if time.Now().After(deadline) {
			p.Kill()
			t.Fatalf("%s is still running", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

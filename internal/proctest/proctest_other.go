//go:build !linux

package proctest

import "testing"

// Process is a process under test. Without pidfds a test cannot hold one
// safely, so Open skips the test.
type Process struct{}

// Open skips the test: only Linux has pidfds.
func Open(t *testing.T, _ int, _ string) *Process {
	t.Helper()
	t.Skip("watching a process safely needs pidfds, which only Linux has")
	return nil
}

// Alive reports false.
func (*Process) Alive() bool { return false }

// Kill does nothing.
func (*Process) Kill() {}

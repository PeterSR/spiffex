package procgroup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/proctest"
)

// The test binary doubles as the commands under test, chosen by its first
// argument.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "child" {
		os.Exit(child(os.Args[2], os.Args[3:]))
	}
	if err := BecomeSubreaper(); err != nil {
		fmt.Fprintln(os.Stderr, "not a subreaper:", err)
	}
	os.Exit(m.Run())
}

func child(mode string, args []string) int {
	switch mode {
	case "escape":
		// Leaves the group, so the kill does not reach it, and exits a
		// little later, after its parent.
		c := exec.Command(os.Args[0], "child", "nap", args[0])
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := c.Start(); err != nil {
			return 3
		}
		_ = os.WriteFile(args[0], []byte(strconv.Itoa(c.Process.Pid)+"\n"), 0o600)
	case "nap":
		time.Sleep(300 * time.Millisecond)
	case "fail":
		return 7
	case "hang":
		time.Sleep(time.Minute)
	}
	return 0
}

func command(ctx context.Context, t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exec.CommandContext(ctx, exe, append([]string{"child"}, args...)...)
}

func TestRunReportsExit(t *testing.T) {
	err := Run(command(context.Background(), t, "fail"))
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Errorf("err = %v, want exit status 7", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Run(command(ctx, t, "hang")); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("a hung command: %v after %s", err, time.Since(start))
	}
}

// A process that left the group is not killed, but once it exits, Sweep
// reaps it instead of leaving a zombie.
func TestSweepReapsEscapees(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "escapee.pid")
	if err := Run(command(context.Background(), t, "escape", pidFile)); err != nil {
		t.Fatal(err)
	}
	// The escapee is this process's child now, so its ID stays its own
	// until Sweep reaps it.
	escapee := proctest.Open(t, proctest.WaitForPID(t, pidFile, time.Second), "nap")
	deadline := time.Now().Add(5 * time.Second)
	for escapee.Alive() {
		if time.Now().After(deadline) {
			escapee.Kill()
			t.Fatal("the escapee was never reaped")
		}
		time.Sleep(50 * time.Millisecond)
		Sweep()
	}
}

func TestCheckKill(t *testing.T) {
	// A program that does nothing: the test binary itself would run the
	// whole suite if it got as far as starting.
	exe, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true to run")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	err = CheckKill(exe, uid, gid)
	switch {
	case os.Getuid() == 0 && err != nil:
		t.Errorf("as root: %v", err)
	case os.Getuid() != 0 && err == nil:
		// Without privilege, dropping supplementary groups already fails;
		// a process that cannot start cannot be checked either.
		t.Error("checked a user without the privilege to change to it")
	}
	if os.Getuid() != 0 {
		return
	}
	// As root, another user's process can be killed.
	if err := CheckKill(exe, 65534, 65534); err != nil {
		t.Errorf("nobody: %v", err)
	}
}

// Group IDs that kill(2) reads as something wider than one group are
// refused, and logged, without sending any signal.
func TestKillGroupRefusesBroadcast(t *testing.T) {
	var buf strings.Builder
	SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	defer SetLogger(slog.Default())
	for _, pgid := range []int{1, 0, -1, -42} {
		if err := killGroup(pgid); !errors.Is(err, errNotAGroup) {
			t.Errorf("killGroup(%d) = %v, want it refused", pgid, err)
		}
	}
	if !strings.Contains(buf.String(), "cannot kill a process group") {
		t.Errorf("log: %q", buf.String())
	}
}

// Package procgroup runs a command in a process group of its own and, once
// it is done, leaves nothing of it behind: every process still in the group
// is killed, and those that are this process's children are reaped.
//
// The group is killed before its leader is reaped where the platform allows
// waiting for an exit without reaping (Linux): a zombie leader keeps its
// process ID, and with it the group's, from being reused, so the kill can
// only reach the group that was started.
//
// A process that left the group (with setsid, say) escapes the kill. When
// this process is a child subreaper (see BecomeSubreaper), such escapees,
// once they exit, are reaped by Sweep, and by Run after every command.
package procgroup

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// reapTimeout bounds the wait for a killed group to disappear.
const reapTimeout = 5 * time.Second

// errNotAGroup refuses a group ID that kill(2) would not read as one group:
// -0 is the caller's own group and -1 is every process the caller may
// signal, so either would kill far more than a command.
var errNotAGroup = errors.New("not the process group of a started command")

var (
	// mu is held while a command starts and while orphans are swept, so a
	// sweep never takes a command's leader for an orphan.
	mu      sync.Mutex
	leaders = map[int]bool{}
	// subreaper is set once this process adopts orphaned descendants.
	subreaper bool
	logger    = slog.Default()
)

// Run starts cmd in a new process group, waits for it as cmd.Wait does, and
// then kills and reaps whatever is left of the group. cmd.Cancel, when cmd
// has a context, kills the whole group. SysProcAttr fields other than
// Setpgid are kept.
func Run(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }

	mu.Lock()
	if err := cmd.Start(); err != nil {
		mu.Unlock()
		return err
	}
	pgid := cmd.Process.Pid
	leaders[pgid] = true
	mu.Unlock()

	killedFirst := awaitExit(pgid)
	if killedFirst {
		_ = killGroup(pgid)
	}
	err := cmd.Wait()
	if !killedFirst {
		_ = killGroup(pgid)
	}
	mu.Lock()
	delete(leaders, pgid)
	mu.Unlock()
	reapGroup(pgid)
	Sweep()
	return err
}

// SetLogger sets where failures to kill a group are logged. The default is
// slog.Default.
func SetLogger(l *slog.Logger) {
	mu.Lock()
	logger = l
	mu.Unlock()
}

// killGroup kills every process in the group. A group already gone is not a
// failure; any other is logged, since what could not be killed goes on
// running.
func killGroup(pgid int) error {
	err := errNotAGroup
	if pgid > 1 {
		err = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		mu.Lock()
		l := logger
		mu.Unlock()
		l.Error("cannot kill a process group", "pgid", pgid, "error", err)
	}
	return err
}

// CheckKill starts a short-lived process as uid and gid and kills it, to
// make sure processes run as that user can be killed from here: otherwise
// a hung one could never be stopped.
func CheckKill(exe string, uid, gid uint32) error {
	cmd := exec.Command(exe)
	// As bare as a verifier: nothing of this process's settings shows in
	// the probe's environment.
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s as %d:%d (the user must be able to execute it, and this process to change to that user): %w", exe, uid, gid, err)
	}
	// Until it is reaped, the process keeps its ID, exited or not.
	killErr := syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Wait()
	if killErr != nil {
		return fmt.Errorf("cannot kill a process running as %d:%d (this needs CAP_KILL, or running as that user): %w", uid, gid, killErr)
	}
	return nil
}

// reapGroup reaps the group's members that are children of this process,
// until no process of the group is left or reapTimeout passes. Members that
// are not its children are reaped by their own parents.
func reapGroup(pgid int) {
	if pgid <= 1 {
		return
	}
	deadline := time.Now().Add(reapTimeout)
	for {
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-pgid, &status, syscall.WNOHANG, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if err != nil || pid <= 0 {
				break
			}
		}
		if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// BecomeSubreaper makes this process adopt its orphaned descendants instead
// of the init process, so that they can be killed with their group and
// reaped here, also when this process is itself init in a container.
func BecomeSubreaper() error {
	if err := setSubreaper(); err != nil {
		return err
	}
	mu.Lock()
	subreaper = true
	mu.Unlock()
	return nil
}

// Sweep reaps adopted descendants that have exited, other than the leaders
// of commands Run is waiting for. It does nothing unless BecomeSubreaper
// succeeded.
func Sweep() {
	mu.Lock()
	defer mu.Unlock()
	if !subreaper {
		return
	}
	for _, pid := range exitedChildren() {
		if leaders[pid] {
			continue
		}
		var status syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
	}
}

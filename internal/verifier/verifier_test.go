package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/procgroup"
	"github.com/PeterSR/spiffex/internal/state"
)

// The test binary doubles as the verifiers under test: started with a first
// argument verifier:<mode>, it behaves as that verifier instead of running
// tests. Verifiers get no environment, so the mode travels as an argument.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		if mode, ok := strings.CutPrefix(os.Args[1], "verifier:"); ok {
			os.Exit(fakeVerifier(mode, os.Args[2:]))
		}
	}
	// As the issuer does when verifiers are installed, so what verifiers
	// leave behind is reaped here.
	if err := procgroup.BecomeSubreaper(); err != nil {
		fmt.Fprintln(os.Stderr, "not a subreaper:", err)
	}
	os.Exit(m.Run())
}

func fakeVerifier(mode string, args []string) int {
	// Checked before anything else opens a file and takes the number.
	inherited := ""
	if len(args) > 0 && mode == "echo" {
		fd, _ := strconv.Atoi(args[0])
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil {
			inherited = "open"
		}
	}
	switch mode {
	case "echo":
		var in map[string]any
		if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
			fmt.Fprintln(os.Stderr, "bad input:", err)
			return 2
		}
		out := map[string]any{"claims": map[string]any{
			"input":     in,
			"env":       len(os.Environ()),
			"own_group": syscall.Getpgrp() == os.Getpid(),
			"inherited": inherited,
			"n":         json.Number("12345678901234567890"),
		}, "ignored": true}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	case "fail":
		fmt.Fprint(os.Stderr, "no such account\nforged: line")
		return 1
	case "sleep":
		// Leaves a child of its own behind, which the timeout must kill too.
		child := exec.Command(os.Args[0], "verifier:orphan", args[0])
		if err := child.Start(); err != nil {
			return 3
		}
		time.Sleep(time.Minute)
	case "background":
		// Leaves a sleeper behind and exits successfully.
		child := exec.Command(os.Args[0], "verifier:orphan", args[0])
		if err := child.Start(); err != nil {
			return 3
		}
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(args[0]); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = os.Stdout.WriteString(`{"claims":{}}`)
	case "orphan":
		_ = os.WriteFile(args[0], []byte(strconv.Itoa(os.Getpid())), 0o600)
		time.Sleep(time.Minute)
	case "big":
		_, _ = os.Stdout.WriteString(`{"claims":{},"pad":"` + strings.Repeat("x", maxOutput) + `"}`)
	case "exact":
		head := `{"claims":{"sub":"a"}}`
		_, _ = os.Stdout.WriteString(head + strings.Repeat(" ", maxOutput-len(head)))
	case "raw":
		_, _ = os.Stdout.WriteString(args[0])
	case "slow":
		time.Sleep(200 * time.Millisecond)
		_, _ = os.Stdout.WriteString(`{"claims":{}}`)
	}
	return 0
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

var client = netip.MustParseAddr("192.0.2.7")

func execOrigin(t *testing.T, timeout time.Duration, args ...string) *state.Expanded {
	t.Helper()
	return &state.Expanded{
		Name: "aws",
		Kind: state.KindExec,
		Exec: &state.ExpandedExec{
			Command:  append([]string{self(t)}, args...),
			Audience: "https://issuer.example.org/origins/aws",
			Timeout:  timeout,
			Params: map[string]state.Strings{
				"account": state.One("123456789012"),
				"regions": state.List("eu-north-1"),
				"none":    state.List(),
			},
		},
	}
}

func newRunner(t *testing.T) *Runner {
	t.Helper()
	r, err := NewRunner(Limits{PerOrigin: 2, Total: 3, PerAddressPerMinute: 600, PerAddressBurst: 100})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func request(origin *state.Expanded, token string) Request {
	return Request{Issuer: "https://issuer.example.org", Origin: origin, SubjectToken: token, Client: client}
}

func TestRunPassesInputAndReturnsClaims(t *testing.T) {
	// A descriptor the test opens without close-on-exec, as one inherited
	// from a parent process would be.
	fd, err := syscall.Open(os.Args[0], syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	r := newRunner(t)
	claims, err := r.Run(context.Background(), request(execOrigin(t, 5*time.Second, "verifier:echo", strconv.Itoa(fd)), "signed-request"))
	if err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(claims["input"])
	want := `{"audience":"https://issuer.example.org/origins/aws","issuer":"https://issuer.example.org","origin":"aws",` +
		`"params":{"account":"123456789012","none":[],"regions":["eu-north-1"]},"subject_token":"signed-request","version":1}`
	if string(in) != want {
		t.Errorf("the verifier read\n%s\nwant\n%s", in, want)
	}
	if claims["env"] != json.Number("0") {
		t.Errorf("the verifier saw %v environment variables, want none", claims["env"])
	}
	if claims["own_group"] != true {
		t.Error("the verifier does not lead a process group of its own")
	}
	if claims["inherited"] != "" {
		t.Error("the verifier inherited a file descriptor beyond standard error")
	}
	if v, _ := state.ClaimValue(claims, "n"); v != "12345678901234567890" {
		t.Errorf("n = %q, want the integer exactly as written", v)
	}
}

func TestRunRejects(t *testing.T) {
	r := newRunner(t)
	cases := map[string]struct {
		origin *state.Expanded
		token  string
	}{
		"exit status":          {execOrigin(t, 5*time.Second, "verifier:fail"), "p"},
		"output too large":     {execOrigin(t, 5*time.Second, "verifier:big"), "p"},
		"no output":            {execOrigin(t, 5*time.Second, "verifier:raw", ""), "p"},
		"two objects":          {execOrigin(t, 5*time.Second, "verifier:raw", `{"claims":{}} {"claims":{}}`), "p"},
		"duplicate member":     {execOrigin(t, 5*time.Second, "verifier:raw", `{"claims":{"a":1,"a":2}}`), "p"},
		"duplicate at the top": {execOrigin(t, 5*time.Second, "verifier:raw", `{"claims":{},"x":1,"x":2}`), "p"},
		"claims not an object": {execOrigin(t, 5*time.Second, "verifier:raw", `{"claims":"a"}`), "p"},
		"no claims":            {execOrigin(t, 5*time.Second, "verifier:raw", `{"other":{}}`), "p"},
		"not UTF-8":            {execOrigin(t, 5*time.Second, "verifier:echo"), "\xff\xfe"},
		"the issuer's own JWT": {execOrigin(t, 5*time.Second, "verifier:echo"), "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyJ9."},
		"command does not run": {&state.Expanded{Name: "x", Exec: &state.ExpandedExec{Command: []string{"/nonexistent/verifier"}, Timeout: time.Second}}, "p"},
		"not an exec origin":   {&state.Expanded{Name: "x"}, "p"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := r.Run(context.Background(), request(c.origin, c.token))
			if !errors.Is(err, ErrRejected) {
				t.Errorf("err = %v, want a rejection", err)
			}
		})
	}
	t.Run("output of exactly the limit", func(t *testing.T) {
		if _, err := r.Run(context.Background(), request(execOrigin(t, 5*time.Second, "verifier:exact"), "p")); err != nil {
			t.Errorf("err = %v; 64 KiB of output is within the limit", err)
		}
	})
	t.Run("standard error in the reason, quoted", func(t *testing.T) {
		_, err := r.Run(context.Background(), request(execOrigin(t, 5*time.Second, "verifier:fail"), "p"))
		if err == nil || !strings.Contains(err.Error(), `no such account\nforged: line`) {
			t.Errorf("err = %v", err)
		}
	})
}

// At the timeout the whole process group goes, including what the verifier
// started.
func TestRunKillsProcessGroupAtTimeout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "orphan.pid")
	r := newRunner(t)
	start := time.Now()
	_, err := r.Run(context.Background(), request(execOrigin(t, 2*time.Second, "verifier:sleep", pidFile), "p"))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("err = %v, want a timeout rejection", err)
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Errorf("Run took %s after a 2s timeout", elapsed)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the verifier's child never ran: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	// Signalling 0 or -1 would reach this process's group, or every process
	// the user owns.
	if err != nil || pid <= 1 {
		t.Fatalf("not a child's process ID: %q", data)
	}
	wantGone(t, pid)
}

// A verifier that succeeds takes what it started with it, and nothing is
// left to reap.
func TestRunKillsWhatASuccessfulVerifierLeaves(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "sleeper.pid")
	r := newRunner(t)
	if _, err := r.Run(context.Background(), request(execOrigin(t, 5*time.Second, "verifier:background", pidFile), "p")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the verifier's child never ran: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	// Signalling 0 or -1 would reach this process's group, or every process
	// the user owns.
	if err != nil || pid <= 1 {
		t.Fatalf("not a child's process ID: %q", data)
	}
	// Gone at once, not even a zombie: Run has killed and reaped it.
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Errorf("the verifier's child is still there after Run: %v", err)
	}
}

// wantGone waits for a process to be gone entirely: killed and reaped.
func wantGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the verifier's child outlived its verifier")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunAsUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root, changing user succeeds")
	}
	r, err := NewRunner(Limits{PerOrigin: 1, Total: 1, PerAddressPerMinute: 60, PerAddressBurst: 1,
		User: &User{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}})
	if err != nil {
		t.Fatal(err)
	}
	// Dropping supplementary groups needs privilege, so the verifier does
	// not start: proof the user change is attempted.
	_, err = r.Run(context.Background(), request(execOrigin(t, 5*time.Second, "verifier:echo"), "p"))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "could not run") {
		t.Errorf("err = %v", err)
	}
}

func TestRunLimits(t *testing.T) {
	r := newRunner(t)
	slow := execOrigin(t, 5*time.Second, "verifier:slow")
	other := execOrigin(t, 5*time.Second, "verifier:slow")
	other.Name = "gcp"
	var wg sync.WaitGroup
	results := make(chan error, 5)
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			origin := slow
			if i >= 2 {
				origin = other
			}
			_, err := r.Run(context.Background(), request(origin, "p"))
			results <- err
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	close(results)
	busy := 0
	for err := range results {
		switch {
		case errors.Is(err, ErrBusy):
			busy++
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		}
	}
	// Two for aws, then one for gcp until the total of three is reached.
	if busy != 2 {
		t.Errorf("%d requests were turned away, want 2", busy)
	}
}

func TestAddressLimiter(t *testing.T) {
	l := newAddressLimiter(1, 3)
	now := time.Now()
	a := netip.MustParseAddr("2001:db8::1")
	sameHost := netip.MustParseAddr("2001:db8::2")
	for i := range 3 {
		if !l.allow(a, now) {
			t.Fatalf("start %d refused within the burst", i)
		}
	}
	if l.allow(sameHost, now) {
		t.Error("another address of the same /64 escaped the limit")
	}
	if !l.allow(netip.MustParseAddr("2001:db9::1"), now) {
		t.Error("another network was limited")
	}
	if !l.allow(a, now.Add(time.Second)) {
		t.Error("no start allowed a second later")
	}
}

func TestNewRunnerRefusesZeroLimits(t *testing.T) {
	if _, err := NewRunner(Limits{PerOrigin: 1, Total: 1, PerAddressPerMinute: 0, PerAddressBurst: 1}); err == nil {
		t.Error("a zero limit was accepted")
	}
}

// A full table forgets the address used longest ago, rather than turning
// new addresses away.
func TestAddressLimiterEvictsTheOldest(t *testing.T) {
	l := newAddressLimiter(1, 1)
	now := time.Now()
	first := netip.MustParseAddr("192.0.2.1")
	if !l.allow(first, now) || l.allow(first, now) {
		t.Fatal("the first address was not limited to its burst")
	}
	for i := range maxAddresses {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if !l.allow(addr, now) {
			t.Fatalf("address %d of a full table was refused", i)
		}
	}
	if l.recent.Len() != maxAddresses {
		t.Errorf("tracking %d addresses, want %d", l.recent.Len(), maxAddresses)
	}
	if !l.allow(first, now) {
		t.Error("the forgotten address was still limited")
	}
}

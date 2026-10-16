// Package verifier runs the exec verifiers of SPEC section 5.4: local
// programs, installed by the operator, that turn a proof spiffex does not
// understand itself into claims. A verifier runs without a shell, with an
// empty environment, in a process group of its own, and with a deadline;
// how many run at once, and how often one client address may start them,
// is bounded.
package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/procgroup"
	"github.com/PeterSR/spiffex/internal/state"
)

const (
	// maxOutput is the most a verifier may write to standard output.
	maxOutput = 64 << 10
	// maxStderrExcerpt is how much of a verifier's standard error is kept
	// for the log.
	maxStderrExcerpt = 1 << 10
	// waitDelay bounds the wait for a verifier's output to close after it
	// exited or was killed, in case it left a process holding it open.
	waitDelay = time.Second
)

// ErrRejected is wrapped by every error that refuses the proof. The rest of
// the message says why, for the log only.
var ErrRejected = errors.New("the proof was rejected")

// ErrBusy means a bound on running verifiers, or on how often the client may
// start them, was reached. The issuer answers server_error.
var ErrBusy = errors.New("too many verifiers are running, or this client starts them too often")

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Limits bound how many verifiers run.
type Limits struct {
	// PerOrigin and Total bound the verifiers running at once, for one
	// origin and in all.
	PerOrigin int
	Total     int
	// PerAddressPerMinute is the rate at which one client address may start
	// verifiers, and PerAddressBurst how many it may start in a row.
	PerAddressPerMinute int
	PerAddressBurst     int
	// User, when set, is the user and group verifiers run as, without
	// supplementary groups. Changing to it needs the privilege to.
	User *User
}

// User is a numeric user and group.
type User struct {
	UID uint32
	GID uint32
}

// Runner runs verifiers within its limits. It is safe for concurrent use.
type Runner struct {
	limits    Limits
	total     chan struct{}
	mu        sync.Mutex
	perOrigin map[string]chan struct{}
	addresses *addressLimiter
	now       func() time.Time
}

// NewRunner returns a Runner with the given limits.
func NewRunner(limits Limits) (*Runner, error) {
	if limits.PerOrigin < 1 || limits.Total < 1 || limits.PerAddressPerMinute < 1 || limits.PerAddressBurst < 1 {
		return nil, errors.New("every verifier limit must be at least 1")
	}
	closeInheritedOnExec()
	return &Runner{
		limits:    limits,
		total:     make(chan struct{}, limits.Total),
		perOrigin: map[string]chan struct{}{},
		addresses: newAddressLimiter(float64(limits.PerAddressPerMinute)/60, float64(limits.PerAddressBurst)),
		now:       time.Now,
	}, nil
}

// Request is one proof to verify.
type Request struct {
	// Issuer is the issuer URL.
	Issuer string
	// Origin is the exec origin named in the request.
	Origin *state.Expanded
	// SubjectToken is the proof, as sent.
	SubjectToken string
	// Client is the address the request came from.
	Client netip.Addr
}

// input is what a verifier reads on its standard input (SPEC section 5.4).
type input struct {
	Version      int                      `json:"version"`
	Issuer       string                   `json:"issuer"`
	Origin       string                   `json:"origin"`
	Audience     string                   `json:"audience"`
	SubjectToken string                   `json:"subject_token"`
	Params       map[string]state.Strings `json:"params"`
}

// Run verifies a proof with the origin's verifier, following SPEC section
// 5.4, and returns the claims it made. An error wrapping ErrRejected
// refuses the proof; ErrBusy means it was not tried.
func (r *Runner) Run(ctx context.Context, req Request) (map[string]any, error) {
	ex := req.Origin.Exec
	if ex == nil {
		return nil, rejected("origin %s is not an exec origin", req.Origin.Name)
	}
	if !utf8.ValidString(req.SubjectToken) {
		return nil, rejected("the proof is not valid UTF-8")
	}
	for _, iss := range exchange.UnverifiedIssuers(req.SubjectToken) {
		if iss == req.Issuer {
			return nil, rejected("the proof is a token of this issuer, which never goes to a verifier")
		}
	}
	if !r.addresses.allow(req.Client, r.now()) {
		return nil, fmt.Errorf("%w: client %s", ErrBusy, req.Client)
	}
	release, ok := r.acquire(req.Origin.Name)
	if !ok {
		return nil, fmt.Errorf("%w: origin %s", ErrBusy, req.Origin.Name)
	}
	defer release()

	params := ex.Params
	if params == nil {
		params = map[string]state.Strings{}
	}
	stdin, err := json.Marshal(input{
		Version:      1,
		Issuer:       req.Issuer,
		Origin:       req.Origin.Name,
		Audience:     ex.Audience,
		SubjectToken: req.SubjectToken,
		Params:       params,
	})
	if err != nil {
		return nil, err
	}
	out, err := run(ctx, ex.Command, ex.Timeout, stdin, r.limits.User)
	if err != nil {
		return nil, err
	}
	return decodeOutput(out)
}

// acquire takes a place among the verifiers running for the origin and in
// total, without waiting.
func (r *Runner) acquire(origin string) (release func(), ok bool) {
	r.mu.Lock()
	sem := r.perOrigin[origin]
	if sem == nil {
		sem = make(chan struct{}, r.limits.PerOrigin)
		r.perOrigin[origin] = sem
	}
	r.mu.Unlock()
	select {
	case sem <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case r.total <- struct{}{}:
	default:
		<-sem
		return nil, false
	}
	return func() {
		<-r.total
		<-sem
	}, true
}

// run starts the verifier and returns what it wrote to standard output, if
// it exited with status 0 in time.
func run(ctx context.Context, argv []string, timeout time.Duration, stdin []byte, user *User) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := &capped{limit: maxOutput, onOverflow: cancel}
	stderr := &capped{limit: maxStderrExcerpt}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if user != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: user.UID, Gid: user.GID, Groups: []uint32{}}}
	}
	cmd.WaitDelay = waitDelay

	// The verifier leads a process group of its own, which goes as a whole
	// at the timeout and after the verifier exits, whatever it started.
	err := procgroup.Run(cmd)
	excerpt := stderr.excerpt()
	switch {
	case stdout.overflowed():
		return nil, rejected("verifier %s wrote more than %d bytes%s", argv[0], maxOutput, excerpt)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, rejected("verifier %s did not finish within %s%s", argv[0], timeout, excerpt)
	case err != nil:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, rejected("verifier %s exited with status %d%s", argv[0], exitErr.ExitCode(), excerpt)
		}
		return nil, rejected("verifier %s could not run: %v%s", argv[0], err, excerpt)
	}
	return stdout.bytes(), nil
}

// decodeOutput accepts exactly one JSON object with a claims member that is
// an object. Duplicated member names anywhere are refused, since parsers
// disagree on which one counts.
func decodeOutput(out []byte) (map[string]any, error) {
	obj, err := state.DecodeClaims(out)
	if err != nil {
		return nil, rejected("the verifier's output: %v", err)
	}
	claims, ok := obj["claims"].(map[string]any)
	if !ok {
		return nil, rejected("the verifier's output has no claims object")
	}
	return claims, nil
}

// capped keeps up to limit bytes written to it and drops the rest, so a
// verifier cannot make the issuer hold more than that.
type capped struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	limit      int
	over       bool
	onOverflow func()
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.buf.Len()
	if len(p) <= room {
		c.buf.Write(p)
		return len(p), nil
	}
	c.buf.Write(p[:max(room, 0)])
	if !c.over {
		c.over = true
		if c.onOverflow != nil {
			c.onOverflow()
		}
	}
	return len(p), nil
}

func (c *capped) overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}

func (c *capped) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

// excerpt returns standard error quoted for a log line, so whatever the
// verifier wrote cannot forge other lines.
func (c *capped) excerpt() string {
	data := c.bytes()
	if len(bytes.TrimSpace(data)) == 0 {
		return ""
	}
	suffix := ""
	if c.overflowed() {
		suffix = " (cut short)"
	}
	return "; standard error: " + strconv.Quote(string(data)) + suffix
}

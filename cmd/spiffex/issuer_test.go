package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/verifier"
)

// At shutdown, a request whose verifier runs past the deadline is
// cancelled, its verifier killed, and shutdown returns only after that.
func TestShutdownEndsVerifiers(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep to run as a verifier")
	}
	runner, err := verifier.NewRunner(verifier.Limits{PerOrigin: 1, Total: 1, PerAddressPerMinute: 60, PerAddressBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	origin := &state.Expanded{Name: "slow", Kind: state.KindExec, Exec: &state.ExpandedExec{Command: []string{sleep, "30"}, Timeout: 30 * time.Second}}
	started := make(chan struct{})
	finished := make(chan error, 1)
	requests, endRequests := context.WithCancel(context.Background())
	defer endRequests()
	srv := &http.Server{
		BaseContext: func(net.Listener) context.Context { return requests },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			_, err := runner.Run(r.Context(), verifier.Request{Issuer: "https://issuer.example.org", Origin: origin,
				SubjectToken: "proof", Client: netip.MustParseAddr("192.0.2.1")})
			finished <- err
		}),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	go func() {
		if resp, err := http.Get("http://" + l.Addr().String()); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never arrived")
	}

	start := time.Now()
	if err := shutdown(srv, endRequests, runner, slog.New(slog.NewTextHandler(io.Discard, nil)), 200*time.Millisecond); err == nil {
		t.Error("shutdown reported that every request finished in time")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("shutdown took %s", elapsed)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Error("the verifier succeeded")
		}
	default:
		t.Error("shutdown returned while the verifier still ran")
	}
}

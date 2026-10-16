package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// runHealth checks that an agent serves the Workload API and has a trust
// bundle. It suits a startup or readiness probe in images without a shell.
func runHealth(ctx context.Context, args []string) error {
	fs := newFlagSet("health", "-socket PATH [-timeout D]")
	socket := fs.String("socket", "", "the agent's Unix socket (required)")
	timeout := fs.Duration("timeout", 3*time.Second, "how long to wait for an answer")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *socket == "" {
		return usageError{errors.New("-socket is required")}
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	path, err := filepath.Abs(*socket)
	if err != nil {
		return err
	}
	_, err = workloadapi.FetchJWTBundles(ctx, workloadapi.WithAddr("unix://"+path))
	return err
}

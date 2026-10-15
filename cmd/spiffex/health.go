package main

import (
	"context"
	"errors"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// runHealth checks that an agent serves the Workload API and has a trust
// bundle. It suits a startup or readiness probe in images without a shell.
func runHealth(ctx context.Context, args []string) error {
	fs := newFlagSet("health", "-socket PATH")
	socket := fs.String("socket", "", "the agent's Unix socket (required)")
	timeout := fs.Duration("timeout", 3*time.Second, "how long to wait for an answer")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("-socket is required")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	_, err := workloadapi.FetchJWTBundles(ctx, workloadapi.WithAddr("unix://"+*socket))
	return err
}

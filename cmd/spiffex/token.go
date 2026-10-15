package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeterSR/spiffex/internal/agent"
)

func runToken(ctx context.Context, args []string) error {
	fs := newFlagSet("token", "-issuer URL -audience AUD (-client-id ID -key-file FILE | -subject-token-file FILE) [flags]")
	creds := addCredentialFlags(fs)
	var audiences stringList
	fs.Var(&audiences, "audience", "audience of the token (required; repeat for several)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(audiences) == 0 {
		return errors.New("-audience is required")
	}
	cred, err := creds.credential()
	if err != nil {
		return err
	}
	td, httpClient, err := creds.issuerTarget()
	if err != nil {
		return err
	}
	client, err := agent.Discover(ctx, *creds.issuerURL, td, httpClient)
	if err != nil {
		return err
	}
	token, err := client.FetchToken(ctx, cred, audiences)
	if err != nil {
		return err
	}
	fmt.Println(token.Value)
	return nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return fmt.Sprint([]string(*l)) }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

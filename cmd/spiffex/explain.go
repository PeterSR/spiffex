package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PeterSR/spiffex/internal/state"
)

// maxSubjectToken matches the largest subject token the issuer accepts.
const maxSubjectToken = 16 << 10

func runExplain(_ context.Context, args []string) error {
	fs := newFlagSet("explain", "-state FILE -token FILE [flags]")
	settings := addSettingsFlags(fs)
	statePath := fs.String("state", "", "the state document (required)")
	tokenPath := fs.String("token", "", "a file holding the subject token, or - for standard input (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *statePath == "" || *tokenPath == "" {
		return usageError{errors.New("-state and -token are required")}
	}
	s, err := settings.load()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*statePath)
	if err != nil {
		return err
	}
	st, err := state.ParseState(data)
	if err != nil {
		return fmt.Errorf("%s:\n%w", *statePath, err)
	}
	token, err := readToken(*tokenPath)
	if err != nil {
		return err
	}
	x, err := state.Explain(st, s, string(token))
	if err != nil {
		return err
	}
	fmt.Print(x)
	if !x.Admitted {
		return errors.New("the token would be refused")
	}
	return nil
}

func readToken(path string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSubjectToken+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSubjectToken {
		return nil, fmt.Errorf("the token is larger than the %d bytes the issuer accepts", maxSubjectToken)
	}
	return data, nil
}

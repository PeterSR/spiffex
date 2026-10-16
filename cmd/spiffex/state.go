package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

func runState(ctx context.Context, args []string) error {
	sub := map[string]func(context.Context, []string) error{
		"export":  stateExport,
		"import":  stateImport,
		"convert": stateConvert,
	}
	if len(args) == 0 || sub[args[0]] == nil {
		fmt.Fprint(os.Stderr, `Usage: spiffex state <command> [flags]

These work on the stored state directly, not through the management API:
whoever runs them needs access to the storage.

  export   print the stored state
  import   replace the stored state with a document, after validating it
  convert  convert a state between a file and a directory tree
`)
		switch {
		case len(args) == 0:
			return usageError{errors.New("no state command given")}
		case args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help":
			return flag.ErrHelp
		}
		return usageError{fmt.Errorf("unknown state command %q", args[0])}
	}
	return sub[args[0]](ctx, args[1:])
}

// openState opens the state the issuer's settings file names.
func openState(config string) (*settings.Settings, store.Store, error) {
	if config == "" {
		return nil, nil, usageError{errors.New("-config is required")}
	}
	s, err := settings.Load(config)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(s.State)
	if err != nil {
		return nil, nil, err
	}
	return s, st, nil
}

// loadParsed loads a stored state and refuses one that does not parse.
func loadParsed(ctx context.Context, st store.Store) (*store.Snapshot, error) {
	snap, err := st.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the state from %s: %w", st, err)
	}
	if snap.Problem != nil {
		return nil, fmt.Errorf("the state in %s does not parse:\n%w", st, snap.Problem)
	}
	return snap, nil
}

func stateExport(ctx context.Context, args []string) error {
	fs := newFlagSet("state export", "-config FILE [-format yaml|json]")
	config := fs.String("config", "", "the issuer's settings file (required)")
	format := fs.String("format", "yaml", "yaml or json")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *format != "yaml" && *format != "json" {
		return usageError{fmt.Errorf("-format %q: want yaml or json", *format)}
	}
	_, st, err := openState(*config)
	if err != nil {
		return err
	}
	snap, err := loadParsed(ctx, st)
	if err != nil {
		return err
	}
	data, err := store.Encode(snap.State, *format == "json")
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "version %q\n", snap.Version)
	return nil
}

func stateImport(ctx context.Context, args []string) error {
	fs := newFlagSet("state import", "-config FILE -f FILE (-if-version VERSION | -force)")
	config := fs.String("config", "", "the issuer's settings file (required)")
	file := fs.String("f", "", "the state document to store, YAML or JSON (required)")
	ifVersion := fs.String("if-version", "", `store only if the stored state is at this version, as state export printed it; "" for a state not stored yet`)
	force := fs.Bool("force", false, "store whatever the stored state is now, without -if-version")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return usageError{errors.New("-f is required")}
	}
	versionGiven := false
	fs.Visit(func(f *flag.Flag) { versionGiven = versionGiven || f.Name == "if-version" })
	if _, ok := os.LookupEnv("SPIFFEX_IF_VERSION"); ok {
		versionGiven = true
	}
	if versionGiven == *force {
		return usageError{errors.New("give -if-version with the version state export printed, or -force to replace whatever is stored")}
	}
	s, st, err := openState(*config)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	doc, err := state.ParseState(data)
	if err != nil {
		return fmt.Errorf("%s:\n%w", *file, err)
	}
	if err := state.Validate(doc, s.Validation).Err(); err != nil {
		return fmt.Errorf("%s is invalid; nothing was stored:\n%w", *file, err)
	}
	if *force {
		// Even when forced, the version just read keeps a change made
		// while this one is stored from being overwritten unseen.
		snap, err := st.Load(ctx)
		if err != nil {
			return fmt.Errorf("reading the state from %s: %w", st, err)
		}
		*ifVersion = snap.Version
	}
	version, err := st.Write(ctx, doc, *ifVersion)
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("the state in %s is not at version %q; nothing was stored", st, *ifVersion)
	}
	if err != nil {
		return err
	}
	fmt.Printf("stored %s in %s, version %q\n", *file, st, version)
	return nil
}

func stateConvert(ctx context.Context, args []string) error {
	fs := newFlagSet("state convert", "(-from-file FILE | -from-dir DIR) (-to-file FILE | -to-dir DIR)")
	fromFile := fs.String("from-file", "", "read the state from this YAML or JSON file")
	fromDir := fs.String("from-dir", "", "read the state from this directory tree")
	toFile := fs.String("to-file", "", "write the state to this file, YAML unless it ends in .json; it must not exist")
	toDir := fs.String("to-dir", "", "write the state as a directory tree here; it must not exist")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if (*fromFile == "") == (*fromDir == "") || (*toFile == "") == (*toDir == "") {
		return usageError{errors.New("give one of -from-file and -from-dir, and one of -to-file and -to-dir")}
	}
	var from, to store.Store = &store.File{Path: filepath.Clean(*fromFile)}, &store.File{Path: filepath.Clean(*toFile)}
	if *fromDir != "" {
		from = &store.Dir{Path: filepath.Clean(*fromDir)}
	}
	if *toDir != "" {
		to = &store.Dir{Path: filepath.Clean(*toDir)}
	}
	snap, err := loadParsed(ctx, from)
	if err != nil {
		return err
	}
	if snap.Version == store.Absent {
		return fmt.Errorf("there is no state in %s", from)
	}
	if _, err := to.Write(ctx, snap.State, store.Absent); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%s exists already; nothing was written", to)
		}
		return err
	}
	fmt.Printf("converted %s to %s\n", from, to)
	return nil
}

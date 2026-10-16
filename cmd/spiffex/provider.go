package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/providers"
)

func runProvider(_ context.Context, args []string) error {
	sub := map[string]func([]string) error{
		"list": providerList,
		"show": providerShow,
	}
	if len(args) == 0 || sub[args[0]] == nil {
		fmt.Fprint(os.Stderr, `Usage: spiffex provider <command>

  list       list the providers spiffex ships with
  show NAME  print a shipped provider's document, as it ships
`)
		switch {
		case len(args) == 0:
			return usageError{errors.New("no provider command given")}
		case args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help":
			return flag.ErrHelp
		}
		return usageError{fmt.Errorf("unknown provider command %q", args[0])}
	}
	return sub[args[0]](args[1:])
}

func providerList(args []string) error {
	fs := newFlagSet("provider list", "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, name := range providers.Names() {
		data, _ := providers.Source(name)
		p, err := state.ParseProvider(data)
		if err != nil {
			return fmt.Errorf("shipped provider %s: %w", name, err)
		}
		summary, _, _ := strings.Cut(p.Description, ". ")
		fmt.Fprintf(w, "%s\t%s\n", name, strings.TrimSuffix(summary, "."))
	}
	return w.Flush()
}

func providerShow(args []string) error {
	fs := newFlagSet("provider show", "NAME")
	rest, err := parseFlagsAndArgs(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usageError{errors.New("name one provider; spiffex provider list lists them")}
	}
	data, ok := providers.Source(rest[0])
	if !ok {
		return fmt.Errorf("no shipped provider is named %q; spiffex provider list lists them", rest[0])
	}
	_, err = os.Stdout.Write(data)
	return err
}

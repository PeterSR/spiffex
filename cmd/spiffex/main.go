// Command spiffex runs the spiffex issuer and agent, and manages their keys.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = ""

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"issuer", "run the issuer", runIssuer},
	{"agent", "run the agent for one workload", runAgent},
	{"token", "fetch a JWT-SVID from the issuer and print it", runToken},
	{"health", "check that an agent is serving, for container probes", runHealth},
	{"key", "generate and manage keys", runKey},
	{"dev", "set up a local trust domain to try spiffex with", runDev},
	{"version", "print the version", runVersion},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "spiffex:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return errors.New("no command given")
		}
		return nil
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	usage(stderr)
	return fmt.Errorf("unknown command %q", args[0])
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: spiffex <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run spiffex <command> -h for the flags of a command.")
}

func runVersion(context.Context, []string) error {
	fmt.Println(versionString())
	return nil
}

func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

// newFlagSet returns a flag set whose flags can also be set through
// SPIFFEX_<NAME> environment variables, which suits containers.
func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet("spiffex "+name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: spiffex %s %s\n\nFlags (each can also be set as SPIFFEX_<FLAG> in the environment):\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args, then fills every flag not given on the command line
// from its environment variable.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		if given[f.Name] || err != nil {
			return
		}
		env := "SPIFFEX_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok {
			if setErr := f.Value.Set(v); setErr != nil {
				err = fmt.Errorf("%s: %w", env, setErr)
			}
		}
	})
	return err
}

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: want debug, info, warn or error", level)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

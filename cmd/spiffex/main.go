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
	{"check", "validate a state document, a provider or an origin", runCheck},
	{"provider", "list the shipped providers and print them", runProvider},
	{"bootstrap", "write the first origin, member and grant to the stored state", runBootstrap},
	{"state", "export, import and convert the stored state", runState},
	{"manage", "read and change the state through the management API", runManage},
	{"explain", "explain how the state treats a subject token", runExplain},
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
		var usage usageError
		if errors.As(err, &usage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return usageError{errors.New("no command given")}
		}
		return nil
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	usage(stderr)
	return usageError{fmt.Errorf("unknown command %q", args[0])}
}

// usageError is a mistake in how spiffex was invoked, as opposed to a failure
// while running; it exits with status 2 instead of 1.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: spiffex <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
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
	rest, err := parseFlagsAndArgs(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return usageError{fmt.Errorf("unexpected argument %q", rest[0])}
	}
	return nil
}

// parseFlagsAndArgs is parseFlags for commands that take arguments after
// their flags, which it returns.
func parseFlagsAndArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err}
	}
	return fs.Args(), fillFromEnvironment(fs)
}

// parseInterleaved is parseFlagsAndArgs for commands whose flags may also
// follow their arguments, as in spiffex manage put origin web -f web.yaml.
// Everything after -- is an argument.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err}
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional, fillFromEnvironment(fs)
}

// fillFromEnvironment sets every flag not given on the command line from
// its environment variable.
func fillFromEnvironment(fs *flag.FlagSet) error {
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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
)

func runCheck(_ context.Context, args []string) error {
	fs := newFlagSet("check", "[-provider | -origin] [flags] FILE...")
	settings := addSettingsFlags(fs)
	providerMode := fs.Bool("provider", false, "each FILE is one provider, named after its file (github.yaml is provider github)")
	originMode := fs.Bool("origin", false, "the first FILE is one origin, named after its file; any others are providers it may use, named after theirs")
	files, err := parseFlagsAndArgs(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usageError{errors.New("name at least one file to check")}
	}
	if *providerMode && *originMode {
		return usageError{errors.New("-provider and -origin do not go together")}
	}
	s, err := settings.load()
	if err != nil {
		return err
	}

	var reports []namedReport
	switch {
	case *originMode:
		r, err := checkOrigin(files, s)
		if err != nil {
			return err
		}
		reports = append(reports, namedReport{files[0], r})
	default:
		for _, file := range files {
			r, err := checkFile(file, *providerMode, s)
			if err != nil {
				return err
			}
			reports = append(reports, namedReport{file, r})
		}
	}
	return printReports(os.Stdout, reports)
}

type namedReport struct {
	file   string
	report *state.Report
}

// checkFile checks a state document, or with asProvider one provider. A file
// that does not parse counts as a report with problems, so the other files
// are still checked.
func checkFile(file string, asProvider bool, s state.Settings) (*state.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if asProvider {
		name, err := objectName(file)
		if err != nil {
			return nil, err
		}
		p, err := state.ParseProvider(data)
		if err != nil {
			return parseFailure(err), nil
		}
		return state.ValidateProvider(name, p, s), nil
	}
	st, err := state.ParseState(data)
	if err != nil {
		return parseFailure(err), nil
	}
	return state.Validate(st, s), nil
}

func checkOrigin(files []string, s state.Settings) (*state.Report, error) {
	name, err := objectName(files[0])
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return nil, err
	}
	o, err := state.ParseOrigin(data)
	if err != nil {
		return parseFailure(err), nil
	}
	providers := map[string]*state.Provider{}
	for _, file := range files[1:] {
		pname, err := objectName(file)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		p, err := state.ParseProvider(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		providers[pname] = p
	}
	return state.ValidateOrigin(name, o, providers, s), nil
}

func parseFailure(err error) *state.Report {
	var problems state.Problems
	if errors.As(err, &problems) {
		return &state.Report{Problems: problems}
	}
	return &state.Report{Problems: state.Problems{{Message: err.Error()}}}
}

// objectName names a provider or origin after its file.
func objectName(file string) (string, error) {
	base := filepath.Base(file)
	for _, ext := range []string{".yaml", ".yml", ".json"} {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		return "", fmt.Errorf("%s: cannot name an object after this file", file)
	}
	return base, nil
}

func printReports(w io.Writer, reports []namedReport) error {
	problems := 0
	for _, nr := range reports {
		prefix := ""
		if len(reports) > 1 {
			prefix = nr.file + ": "
		}
		for _, p := range nr.report.Problems {
			fmt.Fprintf(w, "%s%s\n", prefix, p)
		}
		for _, name := range nr.report.Overrides {
			fmt.Fprintf(w, "%snote: provider %s overrides the shipped provider of that name\n", prefix, name)
		}
		if len(nr.report.Skipped) > 0 {
			fmt.Fprintf(w, "%sskipped: %s\n", prefix, strings.Join(nr.report.Skipped, "; "))
		}
		problems += len(nr.report.Problems)
	}
	switch problems {
	case 0:
		return nil
	case 1:
		return errors.New("1 problem")
	}
	return fmt.Errorf("%d problems", problems)
}

// settingsFlags are the flags that say what validation needs to know about
// the issuer.
type settingsFlags struct {
	file        *string
	issuer      *string
	trustDomain *string
}

func addSettingsFlags(fs *flag.FlagSet) settingsFlags {
	return settingsFlags{
		file:        fs.String("settings", "", "the issuer's settings file, for its issuer, trust_domain, readable_files, bearer_token_files and verifiers"),
		issuer:      fs.String("issuer", "", "the issuer URL (required here or in -settings)"),
		trustDomain: fs.String("trust-domain", "", "the trust domain (required here or in -settings)"),
	}
}

func (f settingsFlags) load() (state.Settings, error) {
	file := &settings.File{}
	if *f.file != "" {
		var err error
		if file, err = settings.ReadFile(*f.file); err != nil {
			return state.Settings{}, err
		}
	}
	if *f.issuer != "" {
		file.Issuer = *f.issuer
	}
	if *f.trustDomain != "" {
		file.TrustDomain = *f.trustDomain
	}
	if file.Issuer == "" || file.TrustDomain == "" {
		return state.Settings{}, usageError{errors.New("the issuer URL and trust domain are required: give -issuer and -trust-domain, or a -settings file with both")}
	}
	if *f.file != "" {
		// The whole file is checked as the issuer would, though validation
		// uses only part of it.
		if err := file.Check(); err != nil {
			return state.Settings{}, fmt.Errorf("%s: %w", *f.file, err)
		}
	}
	s, err := file.Validation()
	if err != nil && *f.file != "" {
		return state.Settings{}, fmt.Errorf("%s: %w", *f.file, err)
	}
	return s, err
}

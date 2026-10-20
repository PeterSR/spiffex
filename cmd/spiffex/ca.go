package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/settings"
)

func runCA(_ context.Context, args []string) error {
	sub := map[string]func([]string) error{
		"init":   caInit,
		"csr":    caCSR,
		"import": caImport,
		"list":   caList,
		"prune":  caPrune,
	}
	if len(args) == 0 || sub[args[0]] == nil || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(os.Stderr, `Usage: spiffex ca <command> [flags]

Make the issuer's certificate authority, for X.509-SVIDs (SPEC section 2.5):
  init      make a self-signed, name-constrained root in the CA directory
  csr       make a key and a certificate request for an intermediate that another CA signs
  import    install the signed certificate of a request made with csr
  list      list the CA certificates, the anchors and their state
  prune     delete CA certificates and keys no verifier can need any more
`)
		switch {
		case len(args) == 0:
			return errors.New("no ca command given")
		case args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help":
			return flag.ErrHelp
		}
		return fmt.Errorf("unknown ca command %q", args[0])
	}
	return sub[args[0]](args[1:])
}

// caOptions are the CA settings as the issuer reads its CA with.
func caOptions(s *settings.Settings) ca.Options {
	return ca.Options{
		Dir:             s.CADir,
		Roots:           s.CARoots,
		RootsDedicated:  s.CARootsDedicated,
		TrustDomain:     s.TrustDomain(),
		ActivationDelay: s.ActivationDelay,
		Retention:       ca.Retention(s.X509SVIDTTL),
	}
}

func parseTrustDomain(name string) (spiffeid.TrustDomain, error) {
	if name == "" {
		return spiffeid.TrustDomain{}, usageError{errors.New("-trust-domain is required")}
	}
	td, err := spiffeid.TrustDomainFromString(name)
	if err != nil {
		return spiffeid.TrustDomain{}, usageError{fmt.Errorf("-trust-domain: %w", err)}
	}
	return td, nil
}

func caInit(args []string) error {
	fs := newFlagSet("ca init", "-dir DIR -trust-domain NAME [flags]")
	dir := fs.String("dir", "", "the issuer's CA directory (required; made if it does not exist)")
	tdName := fs.String("trust-domain", "", "the trust domain the root is for (required)")
	validFor := fs.Duration("valid-for", ca.DefaultRootLifetime, "how long the root is valid, at least 24h; nothing renews it")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError{errors.New("-dir is required")}
	}
	td, err := parseTrustDomain(*tdName)
	if err != nil {
		return err
	}
	c, err := ca.Init(*dir, td, time.Now(), *validFor)
	if err != nil {
		return err
	}
	fmt.Printf("made %s and %s (%s, valid until %s)\n", c.File, c.KeyFile, c.Cert.Subject, c.Cert.NotAfter.Format(time.RFC3339))
	fmt.Println("The issuer publishes the root for activation_delay before it issues X.509-SVIDs from it. Keep the key file readable by the issuer only, and back it up.")
	return nil
}

func caCSR(args []string) error {
	fs := newFlagSet("ca csr", "-dir DIR -trust-domain NAME -out FILE [flags]")
	dir := fs.String("dir", "", "the issuer's CA directory (required; made if it does not exist)")
	tdName := fs.String("trust-domain", "", "the trust domain the intermediate is for (required)")
	alg := fs.String("alg", "ES256", "ES256 (P-256), ES384 (P-384) or RS256 (RSA, 3072 bits)")
	out := fs.String("out", "", "file to write the certificate request to (required; must not exist)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return usageError{errors.New("-dir and -out are required")}
	}
	td, err := parseTrustDomain(*tdName)
	if err != nil {
		return err
	}
	// The file is taken first, so that a request file that cannot be
	// written never leaves a pending key behind.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	keyFile, request, err := ca.NewCSR(*dir, td, keyset.Algorithm(*alg), time.Now())
	if err != nil {
		f.Close()
		_ = os.Remove(*out)
		return err
	}
	if _, err := f.Write(request); err != nil {
		f.Close()
		_ = os.Remove(*out)
		_ = os.Remove(filepath.Join(*dir, keyFile))
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(*out)
		_ = os.Remove(filepath.Join(*dir, keyFile))
		return err
	}
	fmt.Printf("made %s in %s and the request %s\n", keyFile, *dir, *out)
	fmt.Println("Have the request signed as a CA with the extensions it asks for, then install the certificate, followed by any CA certificates between it and the root, with: spiffex ca import")
	return nil
}

// caFlags are the issuer settings the CA commands need. list and prune guess
// nothing: an activation delay or lifetime guessed too short could prune a CA
// that still signs, so they come from the issuer's settings file or must all
// be given. import needs only where the CA is.
type caFlags struct {
	fs                *flag.FlagSet
	config            *string
	dir               *string
	tdName            *string
	roots             *string
	rootsDedicated    *bool
	activationDelay   *time.Duration
	svidTTL           *time.Duration
	needRotationFlags bool
}

func addCAFlags(fs *flag.FlagSet, rotation bool) caFlags {
	f := caFlags{
		fs:                fs,
		config:            fs.String("config", "", "the issuer's settings file, to read ca_dir, ca_roots, ca_roots_dedicated, trust_domain, activation_delay and x509_svid_ttl from"),
		dir:               fs.String("dir", "", "the issuer's CA directory, when not using -config"),
		tdName:            fs.String("trust-domain", "", "the trust domain, when not using -config"),
		roots:             fs.String("roots", "", "the issuer's ca_roots file, when not using -config"),
		rootsDedicated:    fs.Bool("roots-dedicated", false, "the issuer's ca_roots_dedicated, when not using -config"),
		needRotationFlags: rotation,
	}
	if rotation {
		f.activationDelay = fs.Duration("activation-delay", 0, "the issuer's activation_delay, when not using -config")
		f.svidTTL = fs.Duration("x509-svid-ttl", 0, "the issuer's x509_svid_ttl, when not using -config")
	}
	return f
}

func (f caFlags) resolve() (ca.Options, time.Duration, error) {
	given := map[string]bool{}
	f.fs.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	if *f.config != "" {
		for _, name := range []string{"dir", "trust-domain", "roots", "roots-dedicated", "activation-delay", "x509-svid-ttl"} {
			if given[name] {
				return ca.Options{}, 0, errors.New("-config already says what -dir, -trust-domain, -roots, -roots-dedicated, -activation-delay and -x509-svid-ttl would")
			}
		}
		s, err := settings.Load(*f.config)
		if err != nil {
			return ca.Options{}, 0, err
		}
		if s.CADir == "" {
			return ca.Options{}, 0, fmt.Errorf("%s sets no ca_dir", *f.config)
		}
		return caOptions(s), s.X509SVIDTTL, nil
	}
	if *f.dir == "" {
		return ca.Options{}, 0, usageError{errors.New("give -config, or -dir and -trust-domain as the issuer uses them")}
	}
	td, err := parseTrustDomain(*f.tdName)
	if err != nil {
		return ca.Options{}, 0, err
	}
	delay, ttl := settings.DefaultActivationDelay, settings.DefaultX509SVIDTTL
	if f.needRotationFlags {
		if *f.activationDelay <= 0 || *f.svidTTL <= 0 {
			return ca.Options{}, 0, errors.New("give -config, or all of -dir, -trust-domain, -activation-delay and -x509-svid-ttl as the issuer uses them, with -roots and -roots-dedicated if it does")
		}
		delay, ttl = *f.activationDelay, *f.svidTTL
	}
	return ca.Options{
		Dir:             *f.dir,
		Roots:           *f.roots,
		RootsDedicated:  *f.rootsDedicated,
		TrustDomain:     td,
		ActivationDelay: delay,
		Retention:       ca.Retention(ttl),
	}, ttl, nil
}

func caImport(args []string) error {
	fs := newFlagSet("ca import", "-cert FILE (-config FILE | -dir DIR -trust-domain NAME [-roots FILE] [-roots-dedicated])")
	cert := fs.String("cert", "", "the signed certificate, followed by any CA certificates between it and its root, as PEM (required)")
	cf := addCAFlags(fs, false)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *cert == "" {
		return usageError{errors.New("-cert is required")}
	}
	opts, _, err := cf.resolve()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*cert)
	if err != nil {
		return err
	}
	opts.Warn = stderrWarning
	c, err := ca.Import(opts, data, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("installed %s (valid until %s)\n", c.File, c.NotAfter().Format(time.RFC3339))
	fmt.Println("It signs once the root it chains to has been published for activation_delay; a root the issuer already publishes lets it sign at once.")
	return nil
}

func stderrWarning(message string) { fmt.Fprintln(os.Stderr, "warning:", message) }

func caList(args []string) error {
	fs := newFlagSet("ca list", "(-config FILE | -dir DIR -trust-domain NAME -activation-delay D -x509-svid-ttl D [-roots FILE] [-roots-dedicated])")
	cf := addCAFlags(fs, true)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	opts, ttl, err := cf.resolve()
	if err != nil {
		return err
	}
	opts.Warn = stderrWarning
	set, err := ca.Load(opts, time.Now())
	if err != nil {
		return err
	}
	now := time.Now()
	choice, err := set.Select(now, ttl)
	signing := err == nil
	retired := map[string]bool{}
	for _, c := range set.Retired() {
		retired[c.ID] = true
	}
	for _, c := range set.CAs() {
		state := "verifying only"
		switch {
		case retired[c.ID]:
			state = "retired, can be pruned"
		case signing && c.ID == choice.CA.ID:
			state = "signing"
		case !now.Before(c.NotAfter()):
			state = "expired"
		case now.Before(c.Cert.NotBefore):
			state = fmt.Sprintf("not valid until %s", c.Cert.NotBefore.Format(time.RFC3339))
		case !signing || c.Created.After(choice.CA.Created):
			state = fmt.Sprintf("signs from %s", set.SignsFrom(c).Format(time.RFC3339))
		}
		fmt.Printf("%s  %s  %s  %s  until %s\n", c.File, c.Algorithm(), c.ID[:16], state, c.NotAfter().Format("2006-01-02"))
	}
	for _, a := range set.AllAnchors() {
		state := "published"
		if set.AnchorRetired(a) {
			state = "retired, not published"
			if a.Source == ca.RootsSource {
				state += "; remove it from ca_roots"
			}
		}
		fmt.Printf("anchor  %s  %s  %s  %s\n", a.ID[:16], a.Source, a.Cert.Subject, state)
	}
	pending, err := ca.Pending(opts.Dir)
	if err != nil {
		return err
	}
	for _, key := range pending {
		fmt.Printf("%s  waits for its certificate (spiffex ca import)\n", key)
	}
	switch {
	case signing:
	case len(set.CAs()) == 0:
		fmt.Fprintln(os.Stderr, "no CA can sign: none has a key in the directory")
	default:
		fmt.Fprintln(os.Stderr, "no CA can sign: every one is expired, not valid yet or still within its activation delay")
	}
	return nil
}

func caPrune(args []string) error {
	fs := newFlagSet("ca prune", "(-config FILE | -dir DIR -trust-domain NAME -activation-delay D -x509-svid-ttl D [-roots FILE] [-roots-dedicated]) [-dry-run]")
	cf := addCAFlags(fs, true)
	dryRun := fs.Bool("dry-run", false, "only print what would be removed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	opts, _, err := cf.resolve()
	if err != nil {
		return err
	}
	opts.Warn = stderrWarning
	set, err := ca.Load(opts, time.Now())
	if err != nil {
		return err
	}
	if *dryRun {
		for _, c := range set.Retired() {
			fmt.Printf("would remove %s and %s (%s)\n", c.File, c.KeyFile, c.ID[:16])
		}
	} else {
		removed, err := ca.Prune(opts, time.Now())
		for _, c := range removed {
			fmt.Printf("removed %s and %s (%s)\n", c.File, c.KeyFile, c.ID[:16])
		}
		if err != nil {
			return err
		}
	}
	for _, a := range set.AllAnchors() {
		if a.Source == ca.RootsSource && set.AnchorRetired(a) {
			fmt.Printf("ca_roots still lists the retired root %s (%s): remove it, or the issuer publishes it again once nothing here chains to it\n", a.ID[:16], a.Cert.Subject)
		}
	}
	return nil
}

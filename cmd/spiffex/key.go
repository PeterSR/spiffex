package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/settings"
)

func runKey(_ context.Context, args []string) error {
	sub := map[string]func([]string) error{
		"generate": keyGenerate,
		"public":   keyPublic,
		"add":      keyAdd,
		"list":     keyList,
		"prune":    keyPrune,
	}
	if len(args) == 0 || sub[args[0]] == nil || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(os.Stderr, `Usage: spiffex key <command> [flags]

Workload keys (private_key_jwt):
  generate  generate a workload's private key and print its public key
  public    print the public key of a private key file

Issuer signing keys:
  add       add a signing key to the issuer's keys directory
  list      list the signing keys and their state
  prune     delete signing keys no verifier can need any more
`)
		switch {
		case len(args) == 0:
			return errors.New("no key command given")
		case args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help":
			return flag.ErrHelp
		}
		return fmt.Errorf("unknown key command %q", args[0])
	}
	return sub[args[0]](args[1:])
}

func keyGenerate(args []string) error {
	fs := newFlagSet("key generate", "-out FILE [flags]")
	out := fs.String("out", "", "file to write the private key to (required; must not exist)")
	alg := fs.String("alg", "ES256", "ES256 or RS256")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError{errors.New("-out is required")}
	}
	signer, err := keyset.Generate(keyset.Algorithm(*alg))
	if err != nil {
		return err
	}
	if err := writePrivateKey(*out, signer); err != nil {
		return err
	}
	return writePublicKey(os.Stdout, signer.Public())
}

func keyPublic(args []string) error {
	fs := newFlagSet("key public", "-in FILE")
	in := fs.String("in", "", "private key file (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *in == "" {
		return usageError{errors.New("-in is required")}
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	signer, err := keyset.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	return writePublicKey(os.Stdout, signer.Public())
}

func writePrivateKey(path string, signer crypto.Signer) error {
	data, err := keyset.MarshalPrivateKey(signer)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writePublicKey(w io.Writer, pub crypto.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func keyAdd(args []string) error {
	fs := newFlagSet("key add", "-dir DIR [flags]")
	dir := fs.String("dir", "", "the issuer's keys directory (required)")
	alg := fs.String("alg", "ES256", "ES256 or RS256")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError{errors.New("-dir is required")}
	}
	k, err := keyset.Add(*dir, keyset.Algorithm(*alg), time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("added %s (kid %s)\n", k.File, k.ID)
	fmt.Println("It signs once the issuer has published it for activation_delay. Prune older keys only after that, plus token_ttl.")
	return nil
}

// rotationFlags are the issuer settings that decide a signing key's state.
// Guessing them wrong could prune a key the issuer still signs with, so they
// come from the issuer's settings file or must all be given.
type rotationFlags struct {
	fs              *flag.FlagSet
	config          *string
	dir             *string
	activationDelay *time.Duration
	tokenTTL        *time.Duration
}

func addRotationFlags(fs *flag.FlagSet) rotationFlags {
	return rotationFlags{
		fs:              fs,
		config:          fs.String("config", "", "the issuer's settings file, to read keys_dir, activation_delay and token_ttl from"),
		dir:             fs.String("dir", "", "the issuer's keys directory, when not using -config"),
		activationDelay: fs.Duration("activation-delay", 0, "the issuer's activation_delay, when not using -config"),
		tokenTTL:        fs.Duration("token-ttl", 0, "the issuer's token_ttl, when not using -config"),
	}
}

// resolve returns the keys directory, activation delay and retention.
// Retention covers the longest token lifetime, clock skew, and the time it
// takes every issuer process to notice a new key with reload intervals of up
// to a few minutes.
func (f rotationFlags) resolve() (dir string, delay, retention time.Duration, err error) {
	given := map[string]bool{}
	f.fs.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	if *f.config != "" {
		if given["dir"] || given["activation-delay"] || given["token-ttl"] {
			return "", 0, 0, errors.New("-config already says what -dir, -activation-delay and -token-ttl would")
		}
		s, err := settings.Load(*f.config)
		if err != nil {
			return "", 0, 0, err
		}
		return s.KeysDir, s.ActivationDelay, s.TokenTTL + 10*time.Minute, nil
	}
	if *f.dir == "" || *f.activationDelay <= 0 || *f.tokenTTL <= 0 {
		return "", 0, 0, errors.New("give -config, or all of -dir, -activation-delay and -token-ttl as the issuer uses them")
	}
	return *f.dir, *f.activationDelay, *f.tokenTTL + 10*time.Minute, nil
}

func keyList(args []string) error {
	fs := newFlagSet("key list", "(-config FILE | -dir DIR -activation-delay D -token-ttl D)")
	rf := addRotationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, delay, retention, err := rf.resolve()
	if err != nil {
		return err
	}
	set, err := keyset.LoadDir(dir)
	if err != nil {
		return err
	}
	now := time.Now()
	active, signing := set.Active(now, delay)
	retired := map[string]bool{}
	for _, k := range set.Retired(now, delay, retention) {
		retired[k.ID] = true
	}
	for _, k := range set.Keys() {
		state := "verifying only"
		switch {
		case k.Exposed:
			state = "exposed, verifying only"
		case signing && k.ID == active.ID:
			state = "signing"
		case retired[k.ID]:
			state = "retired, can be pruned"
		case !signing || k.Created.After(active.Created):
			state = fmt.Sprintf("signs from %s", k.Published.Add(delay).Format(time.RFC3339))
		}
		fmt.Printf("%s  %s  %s  %s\n", k.File, k.Algorithm, k.ID, state)
	}
	if !signing && len(set.Keys()) > 0 {
		fmt.Fprintln(os.Stderr, "no key can sign: every key is exposed or still within its activation delay")
	}
	return nil
}

func keyPrune(args []string) error {
	fs := newFlagSet("key prune", "(-config FILE | -dir DIR -activation-delay D -token-ttl D) [-dry-run]")
	rf := addRotationFlags(fs)
	dryRun := fs.Bool("dry-run", false, "only print what would be removed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, delay, retention, err := rf.resolve()
	if err != nil {
		return err
	}
	if *dryRun {
		set, err := keyset.LoadDir(dir)
		if err != nil {
			return err
		}
		for _, k := range set.Retired(time.Now(), delay, retention) {
			fmt.Printf("would remove %s (kid %s)\n", k.File, k.ID)
		}
		return nil
	}
	removed, err := keyset.Prune(dir, time.Now(), delay, retention)
	for _, k := range removed {
		fmt.Printf("removed %s (kid %s)\n", k.File, k.ID)
	}
	return err
}

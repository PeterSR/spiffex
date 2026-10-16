package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/manage"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/procgroup"
	"github.com/PeterSR/spiffex/internal/secretperm"
	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/store"
	"github.com/PeterSR/spiffex/internal/verifier"
)

func runIssuer(ctx context.Context, args []string) error {
	fs := newFlagSet("issuer", "-config FILE [flags]")
	configPath := fs.String("config", "", "the issuer's settings file (required)")
	listen := fs.String("listen", ":8443", "address to listen on")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file, reloaded when it changes; without one the issuer serves plain HTTP, for use behind a TLS-terminating proxy")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	reload := fs.Duration("reload-interval", 10*time.Second, "how often to check the state and the keys directory for changes")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *configPath == "" {
		return usageError{errors.New("-config is required")}
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	if *reload <= 0 {
		return errors.New("-reload-interval must be positive")
	}
	logger, err := newLogger(*logLevel)
	if err != nil {
		return err
	}

	s, err := settings.Load(*configPath)
	if err != nil {
		return err
	}
	stateStore, err := store.Open(s.State)
	if err != nil {
		return err
	}
	snap, err := stateStore.Load(ctx)
	if err != nil {
		return fmt.Errorf("reading the state from %s: %w", stateStore, err)
	}
	pol := policy.New(policy.Options{
		Settings:               s.Validation,
		RefusePrivateAddresses: s.RefusePrivateAddresses,
		AllowPrivateHosts:      s.AllowPrivateHosts,
		Logger:                 logger,
	})
	if err := pol.Apply(snap); err != nil {
		return fmt.Errorf("the state in %s is invalid:\n%w", stateStore, err)
	}
	keys, err := keyset.NewWatcher(s.KeysDir, logger)
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	limits := verifier.Limits{
		PerOrigin:           s.VerifierLimits.PerOrigin,
		Total:               s.VerifierLimits.Total,
		PerAddressPerMinute: s.VerifierLimits.PerAddressPerMinute,
		PerAddressBurst:     s.VerifierLimits.PerAddressBurst,
	}
	procgroup.SetLogger(logger)
	if u := s.VerifierUser; u != nil {
		// A verifier the issuer cannot kill would hold its place for good.
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := procgroup.CheckKill(exe, u.UID, u.GID); err != nil {
			return fmt.Errorf("verifier_user: %w", err)
		}
		secrets := []string{}
		if *tlsKey != "" {
			secrets = append(secrets, *tlsKey)
		}
		verifierUser := secretperm.User{UID: u.UID, GID: u.GID}
		if err := secretperm.CheckFiles(verifierUser, s.KeysDir, secrets...); err != nil {
			return fmt.Errorf("verifier_user: %w", err)
		}
		keys.CheckNewKeys(func(path string) error { return secretperm.Check(verifierUser, path) })
		limits.User = &verifier.User{UID: u.UID, GID: u.GID}
	}
	runner, err := verifier.NewRunner(limits)
	if err != nil {
		return err
	}
	if len(s.Validation.Verifiers) > 0 && s.VerifierUser == nil {
		logger.Warn("EXEC VERIFIERS RUN AS THE ISSUER'S OWN USER AND CAN READ ITS SIGNING KEYS: a verifier that is compromised can sign any identity. Set verifier_user to run them as a user that cannot read keys_dir or the TLS key",
			"verifiers", len(s.Validation.Verifiers), "keys_dir", s.KeysDir)
	}
	if len(s.Validation.Verifiers) > 0 {
		// Whatever a verifier leaves behind is then adopted, killed and
		// reaped here, also when the issuer is the container's init.
		if err := procgroup.BecomeSubreaper(); err != nil {
			logger.Warn("cannot adopt what verifiers leave behind", "error", err)
		}
		go sweepOrphans(ctx, *reload)
	}
	var management http.Handler
	if s.Management {
		if management, err = manage.New(manage.Config{
			Settings: s.Validation,
			Store:    stateStore,
			Keys:     keys,
			Policy:   pol,
			Logger:   logger,
		}); err != nil {
			return err
		}
	}
	iss, err := issuer.New(issuer.Config{
		URL:             s.Issuer(),
		Management:      management,
		TrustDomain:     s.TrustDomain(),
		Keys:            keys,
		Policy:          pol,
		Verifiers:       runner,
		TrustedProxies:  s.TrustedProxies,
		TokenTTL:        s.TokenTTL,
		ActivationDelay: s.ActivationDelay,
		Logger:          logger,
	})
	if err != nil {
		return err
	}
	go store.Watch(ctx, stateStore, snap.Version, *reload, logger, pol)
	go func() { _ = keys.Run(ctx, *reload) }()

	// Requests' contexts end at the shutdown deadline at the latest, and
	// with them the verifiers they run.
	requests, endRequests := context.WithCancel(context.Background())
	defer endRequests()
	// The write timeout leaves room for a token request whose exec verifier
	// runs for the longest timeout a provider may set.
	srv := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return requests },
		Addr:              *listen,
		Handler:           iss.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if *tlsCert != "" {
		certs, err := newCertReloader(*tlsCert, *tlsKey)
		if err != nil {
			l.Close()
			return err
		}
		srv.TLSConfig = &tls.Config{GetCertificate: certs.GetCertificate, MinVersion: tls.VersionTLS12}
	}
	if *tlsCert == "" {
		if host, _, _ := net.SplitHostPort(*listen); !isLoopbackHost(host) {
			logger.Warn("serving plain HTTP on a non-loopback address; put a TLS-terminating proxy in front, or use -tls-cert and -tls-key", "address", *listen)
		}
	}
	logger.Info("issuer listening", "address", l.Addr().String(), "tls", *tlsCert != "", "issuer", iss.URL(),
		"trust_domain", iss.TrustDomain().Name(), "state", stateStore.String(), "state_version", snap.Version, "origins", pol.Current().Len(),
		"management", s.Management)
	errc := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errc <- srv.ServeTLS(l, "", "")
		} else {
			errc <- srv.Serve(l)
		}
	}()
	select {
	case err := <-errc:
		// The server failed: no request can finish now.
		endRequests()
		drainVerifiers(runner, logger)
		return err
	case <-ctx.Done():
	}
	return shutdown(srv, endRequests, runner, logger, shutdownGrace)
}

// shutdownGrace is how long requests get to finish when the issuer stops,
// and verifierDrain how long their verifiers then get to be killed and
// reaped.
const (
	shutdownGrace = 10 * time.Second
	verifierDrain = 5 * time.Second
)

// shutdown stops the server, gives requests until the deadline to finish,
// then cancels those left, killing their verifiers, and waits for those to
// be gone, so none outlives the issuer.
func shutdown(srv *http.Server, endRequests context.CancelFunc, runner *verifier.Runner, logger *slog.Logger, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	err := srv.Shutdown(ctx)
	endRequests()
	drainVerifiers(runner, logger)
	return err
}

// drainVerifiers waits a bounded time for running verifiers to finish, and
// logs those that do not: one that ignores the kill must not keep the
// issuer from exiting.
func drainVerifiers(runner *verifier.Runner, logger *slog.Logger) {
	if left := runner.Close(verifierDrain); len(left) > 0 {
		logger.Error("verifiers still run after they were killed; the issuer exits without them", "running_by_origin", left)
	}
}

// sweepOrphans reaps, every interval, descendants that left their
// verifier's process group and exited since.
func sweepOrphans(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			procgroup.Sweep()
		}
	}
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

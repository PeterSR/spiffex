package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/PeterSR/spiffex/internal/config"
	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func runIssuer(ctx context.Context, args []string) error {
	fs := newFlagSet("issuer", "-config FILE [flags]")
	configPath := fs.String("config", "", "configuration file (required)")
	listen := fs.String("listen", ":8443", "address to listen on")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file, reloaded when it changes; without one the issuer serves plain HTTP, for use behind a TLS-terminating proxy")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	reload := fs.Duration("reload-interval", 10*time.Second, "how often to check the configuration and keys directory for changes")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("-config is required")
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

	registry, err := config.NewRegistry(*configPath, logger)
	if err != nil {
		return err
	}
	cfg := registry.Config()
	keys, err := keyset.NewWatcher(cfg.KeysDir, logger)
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	var exchanger issuer.Exchanger
	if len(cfg.Upstreams) > 0 {
		if exchanger, err = exchange.New(cfg.TrustDomain, cfg.Issuer, cfg.Upstreams, logger); err != nil {
			return err
		}
	}
	iss, err := issuer.New(issuer.Config{
		URL:             cfg.Issuer,
		TrustDomain:     cfg.TrustDomain,
		Keys:            keys,
		Clients:         registry,
		Exchanger:       exchanger,
		TokenTTL:        cfg.TokenTTL,
		ActivationDelay: cfg.ActivationDelay,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	go registry.Run(ctx, *reload)
	go func() { _ = keys.Run(ctx, *reload) }()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           iss.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
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
		"trust_domain", iss.TrustDomain().Name(), "clients", len(cfg.Clients), "upstreams", len(cfg.Upstreams))
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
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

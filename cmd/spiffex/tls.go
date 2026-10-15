package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// certReloader serves a certificate from files and loads it again when they
// change, so a renewed certificate (from cert-manager, for one) takes effect
// without a restart. It checks at most every few seconds.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
	// every is the least time between checks of the files.
	every time.Duration
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, every: 5 * time.Second}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) fileStamp() string {
	stamp := ""
	for _, f := range []string{r.certFile, r.keyFile} {
		if info, err := os.Stat(f); err == nil {
			stamp += fmt.Sprintf("%s/%d;", info.ModTime(), info.Size())
		}
	}
	return stamp
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.stamp = &cert, r.fileStamp()
	return nil
}

// GetCertificate implements tls.Config.GetCertificate. A certificate that
// fails to load keeps the previous one in service.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= r.every {
		r.checked = time.Now()
		if r.fileStamp() != r.stamp {
			_ = r.load()
		}
	}
	return r.cert, nil
}

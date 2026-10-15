// Package keyset manages the issuer's signing keys: a directory of PEM files,
// one key per file, named after the moment the key was created.
//
// The file name carries the creation time because file modification times do
// not survive the ways keys are usually delivered (Kubernetes Secret mounts,
// secret managers, backups). A key file is named
//
//	key-20261015T120000Z.pem
//
// and holds a PKCS#8, SEC 1 (EC) or PKCS#1 (RSA) private key.
//
// Every key in the directory is published. The issuer signs with the newest
// key that has been published for at least the activation delay, so verifiers
// that refresh on the published hint learn a key before they meet a token
// signed with it. Removing keys is the operator's call, helped by Prune.
package keyset

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// timeLayout is the creation time format embedded in key file names.
const timeLayout = "20060102T150405Z"

var fileNamePattern = regexp.MustCompile(`^key-(\d{8}T\d{6}Z)\.pem$`)

// Algorithm is a signing algorithm the issuer supports.
type Algorithm string

const (
	ES256 Algorithm = "ES256"
	RS256 Algorithm = "RS256"
)

// Key is one signing key.
type Key struct {
	// ID is the key's RFC 7638 JWK thumbprint (SHA-256, base64url, no padding).
	ID string
	// Created is the creation time from the key's file name.
	Created time.Time
	// Published is the earliest moment verifiers can have seen the key: the
	// later of Created and the file's modification time, or later still if a
	// Watcher saw the key appear after that.
	Published time.Time
	Algorithm Algorithm
	Signer    crypto.Signer
	// File is the base name of the file the key was loaded from.
	File string
}

// Public returns the public half of the key as a JWK.
func (k Key) Public() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       k.Signer.Public(),
		KeyID:     k.ID,
		Algorithm: string(k.Algorithm),
	}
}

// Set is an immutable set of keys, ordered by creation time, oldest first.
// Creation order decides which key is newest; publication time only decides
// when a key may start signing.
type Set struct {
	keys []Key
}

// NewSet builds a set from keys in any order.
func NewSet(keys []Key) (*Set, error) {
	if len(keys) == 0 {
		return nil, errors.New("key set is empty")
	}
	sorted := append([]Key(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].Created.Equal(sorted[j].Created) {
			return sorted[i].Created.Before(sorted[j].Created)
		}
		return sorted[i].ID < sorted[j].ID
	})
	seen := make(map[string]string, len(sorted))
	for _, k := range sorted {
		if other, dup := seen[k.ID]; dup {
			return nil, fmt.Errorf("key %s appears twice (%s and %s)", k.ID, other, k.File)
		}
		seen[k.ID] = k.File
	}
	return &Set{keys: sorted}, nil
}

// Keys returns every key in the set, oldest first.
func (s *Set) Keys() []Key {
	return append([]Key(nil), s.keys...)
}

// Active returns the key to sign with at the given time: the newest key
// published at least activationDelay ago.
//
// When no key qualifies, every key looks recently published. That happens
// when something rewrote all the key files at once (a Kubernetes Secret
// update does) and the process then restarted, and in a freshly created trust
// domain. Active then trusts the creation times in the file names and returns
// the newest key created at least activationDelay ago, which after a rewrite
// is the key that was signing before it; failing that, the oldest key.
func (s *Set) Active(now time.Time, activationDelay time.Duration) Key {
	for i := len(s.keys) - 1; i >= 0; i-- {
		if s.keys[i].activated(now, activationDelay) {
			return s.keys[i]
		}
	}
	for i := len(s.keys) - 1; i >= 0; i-- {
		if !s.keys[i].Created.Add(activationDelay).After(now) {
			return s.keys[i]
		}
	}
	return s.keys[0]
}

func (k Key) activated(now time.Time, activationDelay time.Duration) bool {
	return !k.Published.Add(activationDelay).After(now)
}

// Retired returns the keys no verifier can need any more: keys the issuer
// stopped signing with at least retention ago. A key stops signing when a
// newer key activates. Retention should cover the longest token lifetime plus
// clock skew and the time it takes every issuer process to see a new key.
// The active key and anything newer are never retired.
func (s *Set) Retired(now time.Time, activationDelay, retention time.Duration) []Key {
	active := s.Active(now, activationDelay)
	var retired []Key
	for i, k := range s.keys {
		if k.ID == active.ID || !k.Created.Before(active.Created) {
			break
		}
		// The earliest moment a newer key could have taken over from k.
		var replaced time.Time
		for _, newer := range s.keys[i+1:] {
			at := newer.Published.Add(activationDelay)
			if replaced.IsZero() || at.Before(replaced) {
				replaced = at
			}
		}
		if !replaced.Add(retention).After(now) {
			retired = append(retired, k)
		}
	}
	return retired
}

// IDs returns the key IDs in the set, sorted. Two sets publish the same keys
// exactly when their IDs are equal.
func (s *Set) IDs() []string {
	ids := make([]string, len(s.keys))
	for i, k := range s.keys {
		ids[i] = k.ID
	}
	sort.Strings(ids)
	return ids
}

// LoadDir loads every key file in dir. Files whose names do not match the key
// file pattern are ignored, so the directory can hold other things (a
// Kubernetes Secret mount has hidden ..data entries, for one). A file that
// matches the pattern but cannot be parsed is an error: silently skipping a
// signing key would change which key signs.
func LoadDir(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []Key
	for _, e := range entries {
		m := fileNamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		created, err := time.Parse(timeLayout, m[1])
		if err != nil {
			return nil, fmt.Errorf("%s: bad creation time in file name: %w", e.Name(), err)
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		signer, err := ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		k, err := newKey(signer, created, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		// A file name can claim any age; the modification time says when the
		// key arrived here, which is what activation must count from.
		if mtime := info.ModTime().UTC(); mtime.After(k.Published) {
			k.Published = mtime
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key files (key-<YYYYMMDDTHHMMSSZ>.pem) in %s", dir)
	}
	return NewSet(keys)
}

func newKey(signer crypto.Signer, created time.Time, file string) (Key, error) {
	switch signer.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
	default:
		return Key{}, fmt.Errorf("unsupported private key type %T", signer)
	}
	alg, err := algorithmFor(signer)
	if err != nil {
		return Key{}, err
	}
	kid, err := Thumbprint(signer.Public())
	if err != nil {
		return Key{}, err
	}
	created = created.UTC()
	return Key{ID: kid, Created: created, Published: created, Algorithm: alg, Signer: signer, File: file}, nil
}

func algorithmFor(signer crypto.Signer) (Algorithm, error) {
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported EC curve %s, want P-256", pub.Curve.Params().Name)
		}
		return ES256, nil
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA key of %d bits is too small, want at least 2048", pub.N.BitLen())
		}
		return RS256, nil
	default:
		return "", fmt.Errorf("unsupported key type %T", pub)
	}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a public key,
// base64url-encoded without padding.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// ParsePrivateKey parses a PEM-encoded PKCS#8, SEC 1 or PKCS#1 private key.
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	if _, err := algorithmFor(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

// Generate creates a new private key for the algorithm.
func Generate(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RS256:
		return rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// MarshalPrivateKey encodes a private key as PKCS#8 PEM.
func MarshalPrivateKey(signer crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// FileName returns the key file name for a key created at the given time.
func FileName(created time.Time) string {
	return "key-" + created.UTC().Format(timeLayout) + ".pem"
}

// Add generates a new key, writes it to dir and returns it. The key file is
// written under a temporary name and linked into place, so a crash never
// leaves a half-written key file behind, and an existing file is never
// overwritten.
func Add(dir string, alg Algorithm, now time.Time) (Key, error) {
	signer, err := Generate(alg)
	if err != nil {
		return Key{}, err
	}
	data, err := MarshalPrivateKey(signer)
	if err != nil {
		return Key{}, err
	}
	created := now.UTC().Truncate(time.Second)
	name := FileName(created)

	tmp, err := os.CreateTemp(dir, ".key-*.tmp")
	if err != nil {
		return Key{}, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Key{}, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Key{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Key{}, err
	}
	if err := tmp.Close(); err != nil {
		return Key{}, err
	}
	if err := os.Chtimes(tmp.Name(), created, created); err != nil {
		return Key{}, err
	}
	if err := os.Link(tmp.Name(), filepath.Join(dir, name)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Key{}, fmt.Errorf("%s already exists: key files are named by the second they were created in, so wait a second and try again", name)
		}
		return Key{}, err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return newKey(signer, created, name)
}

// Prune deletes the files of retired keys from dir and returns what it
// removed. It reloads the directory first so it acts on what is on disk now.
func Prune(dir string, now time.Time, activationDelay, retention time.Duration) ([]Key, error) {
	set, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	retired := set.Retired(now, activationDelay, retention)
	for i, k := range retired {
		if err := os.Remove(filepath.Join(dir, k.File)); err != nil {
			return retired[:i], err
		}
	}
	return retired, nil
}

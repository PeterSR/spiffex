package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const testIssuer = "https://issuer.example.org"

func testSettings() Settings { return DefaultSettings(testIssuer, td) }

// check parses and validates a state document, failing the test when it
// does not parse.
func check(t *testing.T, doc string) *Report {
	t.Helper()
	return checkWith(t, doc, testSettings())
}

func checkWith(t *testing.T, doc string, s Settings) *Report {
	t.Helper()
	st, err := ParseState([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, doc)
	}
	return Validate(st, s)
}

// hasProblem reports whether a problem is at path with a message containing
// msg.
func hasProblem(ps Problems, path, msg string) bool {
	for _, p := range ps {
		if p.Path == path && strings.Contains(p.Message, msg) {
			return true
		}
	}
	return false
}

func wantProblem(t *testing.T, r *Report, path, msg string) {
	t.Helper()
	if !hasProblem(r.Problems, path, msg) {
		t.Errorf("want a problem at %q containing %q, got:\n%v", path, msg, r.Problems)
	}
}

func wantValid(t *testing.T, r *Report) {
	t.Helper()
	if len(r.Problems) > 0 {
		t.Errorf("want no problems, got:\n%v", r.Problems)
	}
}

func pemKey(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

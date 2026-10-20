package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"slices"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/edkey"
	"github.com/PeterSR/spiffex/internal/policy"
)

// AuditAttr marks a log record that must be written whatever log level the
// operator chose: the record of an issued X.509-SVID is the only trace of
// it (SPEC section 3.4).
//
// The marker is recognised only as an attribute of the record itself, and
// only on a record logged at Info or above: pass it in the call that logs the
// record, never through Logger.With and never inside a group.
var AuditAttr = slog.Bool("audit", true)

// TokenTypeX509SVID is the requested_token_type and issued_token_type of an
// X.509-SVID (SPEC section 3.4).
const TokenTypeX509SVID = "urn:spiffex:token-type:x509-svid"

const (
	// maxCSR bounds the DER of a certificate signing request (SPEC section
	// 3.4).
	maxCSR = 8 << 10
	// rsaExponent is the only public exponent accepted in a CSR's RSA key.
	rsaExponent = 65537
)

// parseCSR decodes the csr parameter and returns the public key it proves
// possession of. Everything else in the request is ignored (SPEC section
// 3.4). The key is judged before the signature is checked, so that an
// oversized RSA modulus costs nothing.
func parseCSR(raw string) (crypto.PublicKey, error) {
	if len(raw) > base64.RawURLEncoding.EncodedLen(maxCSR) {
		return nil, errInvalidRequest("csr is larger than %d bytes", maxCSR)
	}
	// Go's decoder skips line breaks, which this encoding does not allow.
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errInvalidRequest("csr must be base64url without padding")
		}
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return nil, errInvalidRequest("csr must be base64url without padding")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errInvalidRequest("csr is not a DER certificate request")
	}
	if csr.Version != 0 {
		return nil, errInvalidRequest("csr must be version 1")
	}
	if err := checkCSRKey(csr); err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errInvalidRequest("csr signature does not verify with its own key")
	}
	return csr.PublicKey, nil
}

// checkCSRKey accepts ECDSA on P-256 signed with ecdsa-with-SHA256, ECDSA on
// P-384 signed with ecdsa-with-SHA256 or ecdsa-with-SHA384, pure Ed25519, and
// RSA of 2048 to 4096 bits with exponent 65537 signed with PKCS#1 v1.5 and
// SHA-2 (SPEC section 3.4). RSASSA-PSS is not accepted, and neither is
// another hash with an ECDSA curve.
func checkCSRKey(csr *x509.CertificateRequest) error {
	const wanted = "csr key must be ECDSA on P-256 or P-384, Ed25519, or RSA of 2048 to 4096 bits with exponent 65537"
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// OpenSSL signs a P-384 request with SHA-256 unless told otherwise,
		// so P-384 takes either of the two hashes that fit it.
		var ok bool
		switch pub.Curve {
		case elliptic.P256():
			ok = csr.SignatureAlgorithm == x509.ECDSAWithSHA256
		case elliptic.P384():
			ok = csr.SignatureAlgorithm == x509.ECDSAWithSHA256 || csr.SignatureAlgorithm == x509.ECDSAWithSHA384
		default:
			return errInvalidRequest(wanted)
		}
		if !ok {
			return errInvalidRequest("csr signature algorithm is not accepted for this key")
		}
	case ed25519.PublicKey:
		if csr.SignatureAlgorithm != x509.PureEd25519 {
			return errInvalidRequest("csr signature algorithm is not accepted for this key")
		}
		if err := edkey.Check(pub); err != nil {
			return errInvalidRequest("csr key is not acceptable: %v", err)
		}
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < 2048 || bits > 4096 || pub.E != rsaExponent {
			return errInvalidRequest(wanted)
		}
		switch csr.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		default:
			return errInvalidRequest("csr signature algorithm is not accepted for this key")
		}
	default:
		return errInvalidRequest(wanted)
	}
	return nil
}

// checkCSR parses the csr and refuses a key the issuer already knows: its CA
// and JWT signing keys, and the member keys of every keys origin (SPEC
// section 3.4).
func (iss *Issuer) checkCSR(view *policy.View, cas *ca.Set, raw string) (crypto.PublicKey, error) {
	pub, err := parseCSR(raw)
	if err != nil {
		return nil, err
	}
	if iss.knownKey(view, cas, pub) {
		return nil, errInvalidRequest("csr key is one the issuer already knows; a workload's certificate key must be new")
	}
	return pub, nil
}

func sameKey(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && e.Equal(b)
}

func (iss *Issuer) knownKey(view *policy.View, cas *ca.Set, pub crypto.PublicKey) bool {
	keys, _, _ := iss.cfg.Keys.Current()
	for _, k := range keys.Keys() {
		if sameKey(k.Signer.Public(), pub) {
			return true
		}
	}
	if cas != nil {
		for _, c := range cas.CAs() {
			if sameKey(c.Signer.Public(), pub) {
				return true
			}
			for _, cert := range c.Chain {
				if sameKey(cert.PublicKey, pub) {
					return true
				}
			}
		}
		for _, a := range cas.AllAnchors() {
			if sameKey(a.Cert.PublicKey, pub) {
				return true
			}
		}
	}
	for _, e := range view.Expanded() {
		for _, member := range e.Members {
			for _, k := range member {
				if sameKey(k, pub) {
					return true
				}
			}
		}
	}
	return false
}

// caSnapshot is the certificate authority as of now, or nil when the issuer
// has none. A request uses one snapshot throughout.
func (iss *Issuer) caSnapshot() *ca.Set {
	if iss.cfg.CA == nil {
		return nil
	}
	set, _, _ := iss.cfg.CA.Current()
	return set
}

// hasCA reports whether the set holds a certificate authority that could
// sign, as opposed to none configured or none left with a key (SPEC section
// 2.5).
func hasCA(set *ca.Set) bool { return set != nil && len(set.CAs()) > 0 }

// issueX509 answers a token request for an X.509-SVID with the certificate
// chain (SPEC section 3.4).
func (iss *Issuer) issueX509(w http.ResponseWriter, g *grant) {
	now := iss.cfg.Now()
	choice, err := g.ca.Select(now, iss.cfg.X509SVIDTTL)
	if err == nil {
		var leaf *x509.Certificate
		if leaf, err = ca.IssueLeaf(choice, g.id, g.x509Key, now); err == nil {
			iss.respondX509(w, g, choice, leaf)
			return
		}
	}
	if errors.Is(err, ca.ErrExpiring) || errors.Is(err, ca.ErrNoSigningCA) {
		iss.cfg.Logger.Error("no X.509-SVID can be issued", "spiffe_id", g.id, "origin", g.origin.Name, "error", err)
	} else {
		iss.cfg.Logger.Error("issuing an X.509-SVID failed", "spiffe_id", g.id, "origin", g.origin.Name, "error", err)
	}
	writeJSON(w, http.StatusInternalServerError, &oauthError{Code: "server_error"}, "no-store")
}

func (iss *Issuer) respondX509(w http.ResponseWriter, g *grant, choice ca.Choice, leaf *x509.Certificate) {
	chain := slices.Clone(leaf.Raw)
	for _, c := range choice.CA.Chain {
		chain = append(chain, c.Raw...)
	}
	iss.cfg.Logger.Info("issued X.509-SVID", AuditAttr, "serial", hex.EncodeToString(leaf.SerialNumber.Bytes()), "spiffe_id", g.id,
		"origin", g.origin.Name, "not_after", leaf.NotAfter.UTC())
	if choice.Shortened && iss.warnLog.allow(iss.cfg.Now()) {
		iss.cfg.Logger.Warn("the signing CA's chain ends before a full X.509-SVID lifetime; issuing a shorter one", "ca", choice.CA.File, "not_after", leaf.NotAfter.UTC())
	}
	if leaf.Subject.CommonName == "" {
		if _, warned := iss.noCommonName.LoadOrStore(g.origin.Name, true); !warned {
			iss.cfg.Logger.Warn("issued an X.509-SVID without a common name: the SPIFFE ID is longer than 64 characters", "spiffe_id", g.id, "origin", g.origin.Name)
		}
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:     base64.RawURLEncoding.EncodeToString(chain),
		IssuedTokenType: TokenTypeX509SVID,
		TokenType:       "N_A",
		ExpiresIn:       int(math.Ceil(leaf.NotAfter.Sub(iss.cfg.Now()).Seconds())),
		SPIFFEID:        g.id.String(),
	}, "no-store")
}

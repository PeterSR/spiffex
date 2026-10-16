package state

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxMemberKeys = 10
	maxJWKSKeys   = 100
)

// parseMemberKey parses a member's public key (SPEC section 4.2): a PEM
// PUBLIC KEY block given as a JSON string, or a JWK given as an object. Only
// ES256 keys on P-256 and RS256 keys of at least 2048 bits are accepted.
func parseMemberKey(raw json.RawMessage) (crypto.PublicKey, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return parsePEMPublicKey([]byte(text))
	}
	if err := refusePrivateMembers(raw); err != nil {
		return nil, err
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("not a valid JWK: %w", err)
	}
	if !jwk.IsPublic() {
		return nil, errors.New("the JWK holds a private key; give only the public key")
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return nil, fmt.Errorf("the JWK has use %q, want sig", jwk.Use)
	}
	if err := checkMemberKey(jwk.Key); err != nil {
		return nil, err
	}
	want := string(jose.RS256)
	if _, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		want = string(jose.ES256)
	}
	if jwk.Algorithm != "" && jwk.Algorithm != want {
		return nil, fmt.Errorf("the JWK has alg %q, want %s for this key", jwk.Algorithm, want)
	}
	return jwk.Key, nil
}

// privateJWKMembers are the JWK members that carry private key material
// (RFC 7518 section 6).
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth"}

// refusePrivateMembers refuses a JWK that carries private key material, even
// where the key type would not use it: a public document is no place for it.
func refusePrivateMembers(raw json.RawMessage) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return fmt.Errorf("not a valid JWK: %w", err)
	}
	for _, name := range privateJWKMembers {
		if _, ok := members[name]; ok {
			return fmt.Errorf("the JWK has private member %q; give only the public key", name)
		}
	}
	return nil
}

func parsePEMPublicKey(data []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("more than one PEM block; give each key separately")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type %q, want PUBLIC KEY", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := checkMemberKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func checkMemberKey(key any) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("EC curve %s, want P-256", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key of %d bits is too small, want at least 2048", k.N.BitLen())
		}
	default:
		return fmt.Errorf("unsupported key type %T, want an EC P-256 or RSA public key", key)
	}
	return nil
}

// parseJWKS parses an inline JWK Set of an upstream. Its keys must be public
// and asymmetric; which algorithms the upstream signs with is its business.
func parseJWKS(raw json.RawMessage) (*jose.JSONWebKeySet, error) {
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("not a valid JWK Set: %w", err)
	}
	for i, k := range keys.Keys {
		if err := refusePrivateMembers(k); err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a valid JWK Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the JWK Set has no keys")
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("the JWK Set has %d keys, more than the %d allowed", len(set.Keys), maxJWKSKeys)
	}
	for i, k := range set.Keys {
		if !k.IsPublic() {
			return nil, fmt.Errorf("key %d is not a public key", i)
		}
	}
	return &set, nil
}

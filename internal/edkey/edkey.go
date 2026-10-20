// Package edkey judges Ed25519 public keys that come from outside.
package edkey

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

// Check refuses an Ed25519 public key that is not a point of the curve in its
// canonical encoding, or is of small order. Go's ed25519.Verify is
// cofactorless and accepts a signature made without any private key under
// such a key (the identity with R the identity and S zero verifies every
// message), so a proof of possession proves nothing for them. Every place that
// takes an Ed25519 key from a requester must call it.
func Check(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("an Ed25519 key is 32 bytes")
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return errors.New("not a point of the curve")
	}
	if !bytes.Equal(p.Bytes(), pub) {
		return errors.New("not the canonical encoding of the point")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("a point of small order")
	}
	return nil
}

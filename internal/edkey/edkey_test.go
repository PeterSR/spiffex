package edkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
)

func le32(n *big.Int) []byte {
	b := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func withSign(b []byte) []byte {
	c := append([]byte(nil), b...)
	c[31] |= 0x80
	return c
}

// The eight points of order dividing 8, in both signs where they differ, and
// the non-canonical encodings libsodium blocks, are all refused.
func TestCheckRefusesSmallOrderKeys(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	order8a := mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	order8b := mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	identity := le32(big.NewInt(1))
	minusOne := le32(new(big.Int).Sub(p, big.NewInt(1)))
	zero := le32(big.NewInt(0))

	canonical := map[string][]byte{
		"identity":         identity,
		"order 2":          minusOne,
		"order 4":          zero,
		"order 4, other x": withSign(zero),
		"order 8 a":        order8a,
		"order 8 a, other": withSign(order8a),
		"order 8 b":        order8b,
		"order 8 b, other": withSign(order8b),
	}
	for name, key := range canonical {
		if err := Check(key); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// Each of the eight must really be of small order, or the list is wrong.
		pt, err := new(edwards25519.Point).SetBytes(key)
		if err != nil {
			t.Errorf("%s does not decode: %v", name, err)
			continue
		}
		if new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) != 1 {
			t.Errorf("%s is not of small order", name)
		}
	}

	nonCanonical := map[string][]byte{
		"x=0 with the sign bit":      withSign(identity),
		"order 2, x=0 with the sign": withSign(minusOne),
		"y=p":                        le32(p),
		"y=p, sign":                  withSign(le32(p)),
		"y=p+1":                      le32(new(big.Int).Add(p, big.NewInt(1))),
		"y=p+1, sign":                withSign(le32(new(big.Int).Add(p, big.NewInt(1)))),
	}
	for name, key := range nonCanonical {
		if err := Check(key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A point of full order with y+p still below 2^255 has a second encoding.
	found := false
	for y := int64(2); y < 19; y++ {
		good := le32(big.NewInt(y))
		if _, err := new(edwards25519.Point).SetBytes(good); err != nil || Check(good) != nil {
			continue
		}
		found = true
		if err := Check(le32(new(big.Int).Add(p, big.NewInt(y)))); err == nil {
			t.Errorf("the non-canonical encoding of y=%d was accepted", y)
		}
	}
	if !found {
		t.Error("no point with a small y to test non-canonical encodings with")
	}
}

func TestCheckAcceptsOrdinaryKeys(t *testing.T) {
	for range 50 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := Check(pub); err != nil {
			t.Fatal(err)
		}
	}
	if Check(make([]byte, 31)) == nil || Check(nil) == nil {
		t.Error("a key of the wrong length was accepted")
	}
}

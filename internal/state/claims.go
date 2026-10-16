package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// forbiddenOwnerClaims say nothing about who obtained a token (SPEC
// section 5.3).
var forbiddenOwnerClaims = []string{"iss", "aud", "azp", "exp", "iat", "nbf", "jti"}

// splitClaimPath splits a claim path into the JSON object member names it
// names. As in a JSON Pointer (RFC 6901), ~1 stands for / and ~0 for ~ within
// a name; any other ~ is an error.
func splitClaimPath(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("a claim path cannot be empty")
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("claim path %q has an empty member name", path)
		}
		var b strings.Builder
		for j := 0; j < len(part); j++ {
			if part[j] != '~' {
				b.WriteByte(part[j])
				continue
			}
			if j+1 == len(part) || part[j+1] != '0' && part[j+1] != '1' {
				return nil, fmt.Errorf("claim path %q: ~ must be followed by 0 or 1", path)
			}
			if part[j+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			j++
		}
		parts[i] = b.String()
	}
	return parts, nil
}

// checkClaimPath checks a claim path (SPEC section 4.3).
func checkClaimPath(path string) error {
	_, err := splitClaimPath(path)
	return err
}

func checkOwnerClaim(path string) error {
	if err := checkClaimPath(path); err != nil {
		return err
	}
	if slices.Contains(forbiddenOwnerClaims, path) {
		return fmt.Errorf("%s cannot be an owner claim: it says nothing about who obtained the token", path)
	}
	return nil
}

// DecodeClaims decodes a JWT payload, or a verifier's claims, keeping numbers
// exactly as written so that integer claims compare as text. It refuses
// anything but a single JSON object, and member names that appear twice in
// any object, since JSON parsers disagree on which of the two wins.
func DecodeClaims(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	v, err := decodeDepth(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	claims, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("claims: not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("claims: data after the JSON object")
	}
	return claims, nil
}

// maxClaimsDepth bounds nesting, so a hostile payload cannot exhaust the
// stack.
const maxClaimsDepth = 64

func decodeDepth(dec *json.Decoder, depth int) (any, error) {
	if depth > maxClaimsDepth {
		return nil, errors.New("nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		obj := map[string]any{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := keyTok.(string)
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("member %q appears twice", key)
			}
			if obj[key], err = decodeDepth(dec, depth+1); err != nil {
				return nil, err
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			v, err := decodeDepth(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return list, nil
	}
	return tok, nil
}

var integerRE = regexp.MustCompile(`^-?[0-9]+$`)

// ClaimValue returns the value of the claim at path (SPEC section 4.3): a
// non-empty string, or an integer exactly as the token wrote it. Any other
// JSON value, and an empty string, count as absent, so no two different
// values can read the same and an empty claim never identifies anyone.
// Claims must come from DecodeClaims, or numbers will not be found.
func ClaimValue(claims map[string]any, path string) (string, bool) {
	names, err := splitClaimPath(path)
	if err != nil {
		return "", false
	}
	var cur any = claims
	for _, name := range names {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = obj[name]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, v != ""
	case json.Number:
		if integerRE.MatchString(v.String()) {
			return v.String(), true
		}
	}
	return "", false
}

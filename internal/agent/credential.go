package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Grant parameters, as in SPEC section 3.
const (
	grantClientCredentials = "client_credentials"
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	clientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

// assertionLifetime is the lifetime of the client assertions the agent signs:
// long enough to survive clock skew and a slow round trip, short enough that
// an intercepted assertion is useless soon.
const assertionLifetime = time.Minute

// Credential is how the agent proves the workload's identity to the issuer.
// It returns the grant parameters of one token request; the agent adds the
// audiences.
type Credential interface {
	validate() error
	grantParams(issuerURL string, now time.Time) (url.Values, error)
}

// PrivateKeyJWT authenticates with a client assertion signed by the
// workload's private key (SPEC section 3.2).
type PrivateKeyJWT struct {
	ClientID string
	Key      crypto.Signer
}

func (c PrivateKeyJWT) validate() error {
	if c.ClientID == "" {
		return errors.New("a client id is required")
	}
	_, err := c.algorithm()
	return err
}

func (c PrivateKeyJWT) algorithm() (jose.SignatureAlgorithm, error) {
	switch k := c.Key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("EC curve %s, want P-256", k.Curve.Params().Name)
		}
		return jose.ES256, nil
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA key of %d bits is too small, want at least 2048", k.N.BitLen())
		}
		return jose.RS256, nil
	}
	return "", fmt.Errorf("unsupported client key type %T", c.Key)
}

func (c PrivateKeyJWT) grantParams(issuerURL string, now time.Time) (url.Values, error) {
	alg, err := c.algorithm()
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: c.Key},
		(&jose.SignerOptions{}).WithType("client-authentication+jwt"),
	)
	if err != nil {
		return nil, err
	}
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   c.ClientID,
		Subject:  c.ClientID,
		Audience: jwt.Audience{issuerURL},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(assertionLifetime)),
		ID:       rand.Text(),
	}).Serialize()
	if err != nil {
		return nil, err
	}
	return url.Values{
		"grant_type":            {grantClientCredentials},
		"client_id":             {c.ClientID},
		"client_assertion_type": {clientAssertionJWT},
		"client_assertion":      {assertion},
	}, nil
}

// SubjectTokenFile exchanges a token read from a file (SPEC section 3.3). The
// file is read for every request, because the platforms that provide such
// tokens (a Kubernetes projected service account token, for one) rotate them
// in place.
type SubjectTokenFile struct {
	Path string
}

func (c SubjectTokenFile) validate() error {
	if c.Path == "" {
		return errors.New("a subject token file is required")
	}
	return nil
}

func (c SubjectTokenFile) grantParams(string, time.Time) (url.Values, error) {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		return nil, fmt.Errorf("reading the subject token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("the subject token file is empty")
	}
	return url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {token},
		"subject_token_type": {tokenTypeJWT},
	}, nil
}

package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/PeterSR/spiffex/internal/procgroup"
)

// Grant parameters, as in SPEC section 3.
const (
	grantClientCredentials = "client_credentials"
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	clientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeExec          = "urn:spiffex:token-type:exec"
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

// maxSubjectToken is the largest subject token the issuer accepts.
const maxSubjectToken = 16 << 10

// subjectTokenTimeout bounds a subject token command.
const subjectTokenTimeout = 10 * time.Second

// SubjectToken exchanges a proof the workload already has (SPEC section
// 3.3), read for every request: from a file, which platforms such as
// Kubernetes rotate in place, or from the output of a command, for proofs
// that must be made fresh.
type SubjectToken struct {
	// File holds the proof.
	File string
	// Command, when set instead of File, is run without a shell, and its
	// standard output, trimmed, is the proof. It inherits the agent's
	// environment.
	Command []string
	// Origin names the exec origin the proof is for. It is empty for a JWT.
	Origin string
}

func (c SubjectToken) validate() error {
	if (c.File == "") == (len(c.Command) == 0) {
		return errors.New("give either a subject token file or a subject token command")
	}
	if len(c.Command) > 0 && c.Command[0] == "" {
		return errors.New("the subject token command is empty")
	}
	return nil
}

func (c SubjectToken) grantParams(string, time.Time) (url.Values, error) {
	token, err := c.read()
	if err != nil {
		return nil, err
	}
	params := url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {token},
		"subject_token_type": {tokenTypeJWT},
	}
	if c.Origin != "" {
		params.Set("subject_token_type", tokenTypeExec)
		params.Set("origin", c.Origin)
	}
	return params, nil
}

func (c SubjectToken) read() (string, error) {
	var data []byte
	var err error
	if c.File != "" {
		if data, err = os.ReadFile(c.File); err != nil {
			return "", fmt.Errorf("reading the subject token: %w", err)
		}
	} else if data, err = runCommand(c.Command); err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	switch {
	case token == "":
		return "", errors.New("the subject token is empty")
	case len(token) > maxSubjectToken:
		return "", fmt.Errorf("the subject token is larger than the %d bytes the issuer accepts", maxSubjectToken)
	}
	return token, nil
}

// runCommand runs a subject token command and returns its standard output.
func runCommand(argv []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), subjectTokenTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout := &limitedBuffer{limit: maxSubjectToken}
	stderr := &limitedBuffer{limit: 512}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	// In a process group of its own, so that the timeout, and the command
	// finishing, take whatever it started with it.
	err := procgroup.Run(cmd)
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("the subject token command did not finish within %s", subjectTokenTimeout)
	case err != nil:
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("the subject token command: %w: %q", err, msg)
		}
		return nil, fmt.Errorf("the subject token command: %w", err)
	case stdout.over:
		return nil, fmt.Errorf("the subject token command wrote more than the %d bytes the issuer accepts", maxSubjectToken)
	}
	return stdout.Bytes(), nil
}

// limitedBuffer keeps the first limit bytes written to it and drops the
// rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
	over  bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.Len()
	if len(p) > room {
		b.over = true
	}
	b.Buffer.Write(p[:max(0, min(room, len(p)))])
	return len(p), nil
}

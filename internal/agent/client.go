package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

const (
	// maxResponseBody bounds every response read from the issuer.
	maxResponseBody = 1 << 20
	// requestTimeout bounds every request to the issuer, whatever HTTP
	// client the caller supplied.
	requestTimeout = 30 * time.Second
	// maxDescription bounds issuer error text passed on to workloads.
	maxDescription = 200
)

// refusalCodes are the token endpoint errors that mean the issuer refused
// the request, rather than failed (SPEC sections 3.1 and 5).
var refusalCodes = []string{"invalid_client", "invalid_request", "invalid_target", "unsupported_grant_type"}

// IssuerClient talks to a spiffex issuer: discovery, the token endpoint and
// the bundle endpoint.
type IssuerClient struct {
	issuerURL  string
	httpClient *http.Client

	tokenEndpoint  string
	bundleEndpoint string
	trustDomain    spiffeid.TrustDomain
}

// RejectedError is returned when the issuer refused a token request, as
// opposed to failing or being unreachable.
type RejectedError struct {
	Code        string
	Description string
}

func (e *RejectedError) Error() string {
	if e.Description == "" {
		return "issuer refused the request: " + e.Code
	}
	return "issuer refused the request: " + e.Code + ": " + e.Description
}

// CredentialError is a failure to produce the workload's proof of identity
// locally, before anything was sent to the issuer.
type CredentialError struct{ Err error }

func (e *CredentialError) Error() string { return "workload credential: " + e.Err.Error() }
func (e *CredentialError) Unwrap() error { return e.Err }

// Discover reads the issuer's discovery document and returns a client for
// it. trustDomain may be zero, in which case the trust domain the issuer
// announces is used; otherwise the two must agree.
//
// The issuer URL must use https, except on a loopback address. The client
// never follows redirects, so a credential is only ever sent to the issuer's
// own endpoints.
func Discover(ctx context.Context, issuerURL string, trustDomain spiffeid.TrustDomain, httpClient *http.Client) (*IssuerClient, error) {
	if err := checkIssuerURL(issuerURL); err != nil {
		return nil, err
	}
	var client http.Client
	if httpClient != nil {
		client = *httpClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	var doc struct {
		Issuer         string `json:"issuer"`
		TokenEndpoint  string `json:"token_endpoint"`
		BundleEndpoint string `json:"spiffe_bundle_endpoint"`
		TrustDomain    string `json:"spiffe_trust_domain"`
	}
	if err := getJSON(ctx, &client, issuerURL+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != issuerURL {
		return nil, fmt.Errorf("discovery: issuer %q does not match the configured %q", doc.Issuer, issuerURL)
	}
	for _, endpoint := range []string{doc.TokenEndpoint, doc.BundleEndpoint} {
		if !strings.HasPrefix(endpoint, issuerURL+"/") {
			return nil, fmt.Errorf("discovery: endpoint %q is not under the issuer URL", endpoint)
		}
	}
	announced, err := spiffeid.TrustDomainFromString(doc.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("discovery: spiffe_trust_domain: %w", err)
	}
	if !trustDomain.IsZero() && trustDomain != announced {
		return nil, fmt.Errorf("discovery: issuer serves trust domain %s, configured %s", announced, trustDomain)
	}
	return &IssuerClient{
		issuerURL:      issuerURL,
		httpClient:     &client,
		tokenEndpoint:  doc.TokenEndpoint,
		bundleEndpoint: doc.BundleEndpoint,
		trustDomain:    announced,
	}, nil
}

func checkIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("issuer URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("issuer URL %q: plain http is only allowed on a loopback address", raw)
	}
	return fmt.Errorf("issuer URL %q: scheme must be https", raw)
}

// URL returns the issuer URL.
func (c *IssuerClient) URL() string { return c.issuerURL }

// TrustDomain returns the issuer's trust domain.
func (c *IssuerClient) TrustDomain() spiffeid.TrustDomain { return c.trustDomain }

// selfAudience reports whether aud names the issuer itself, which the issuer
// would refuse.
func (c *IssuerClient) selfAudience(aud string) bool {
	return aud == c.issuerURL || aud == c.tokenEndpoint
}

// Token is an issued JWT-SVID.
type Token struct {
	Value    string
	SPIFFEID spiffeid.ID
	Expires  time.Time
	Lifetime time.Duration
}

// FetchToken requests a JWT-SVID for the audiences.
func (c *IssuerClient) FetchToken(ctx context.Context, cred Credential, audiences []string) (Token, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	now := time.Now()
	form, err := cred.grantParams(c.issuerURL, now)
	if err != nil {
		return Token{}, &CredentialError{err}
	}
	form["audience"] = audiences

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return Token{}, err
	}

	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Code        string `json:"error"`
			Description string `json:"error_description"`
		}
		refused := (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) &&
			json.Unmarshal(body, &oe) == nil && slices.Contains(refusalCodes, oe.Code)
		if refused {
			return Token{}, &RejectedError{Code: oe.Code, Description: truncate(oe.Description, maxDescription)}
		}
		return Token{}, fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		SPIFFEID    string `json:"spiffe_id"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return Token{}, fmt.Errorf("token endpoint: %w", err)
	}
	// The token itself is what workloads present, so its claims are what
	// counts; the response fields only have to agree with them.
	svid, err := jwtsvid.ParseInsecure(tr.AccessToken, audiences)
	if err != nil {
		return Token{}, fmt.Errorf("token endpoint: %w", err)
	}
	if !svid.ID.MemberOf(c.trustDomain) || svid.ID.String() != tr.SPIFFEID {
		return Token{}, fmt.Errorf("token endpoint: issued %s (response says %q) outside trust domain %s or inconsistent", svid.ID, tr.SPIFFEID, c.trustDomain)
	}
	if !svid.Expiry.After(now) {
		return Token{}, errors.New("token endpoint: issued an expired token")
	}
	return Token{Value: tr.AccessToken, SPIFFEID: svid.ID, Expires: svid.Expiry, Lifetime: svid.Expiry.Sub(now)}, nil
}

// FetchBundle fetches the trust domain's SPIFFE bundle.
func (c *IssuerClient) FetchBundle(ctx context.Context) (*spiffebundle.Bundle, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.bundleEndpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle endpoint: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}
	bundle, err := spiffebundle.Parse(c.trustDomain, body)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}
	if len(bundle.JWTAuthorities()) == 0 {
		return nil, errors.New("bundle endpoint: the bundle has no JWT authorities")
	}
	return bundle, nil
}

func getJSON(ctx context.Context, client *http.Client, rawURL string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/PeterSR/spiffex/internal/state"
)

// ConfigMapKey is the one key of a state ConfigMap.
const ConfigMapKey = "state.yaml"

// requestTimeout bounds each request to the Kubernetes API.
const requestTimeout = 15 * time.Second

// ConfigMap keeps the state in a Kubernetes ConfigMap, under the key
// state.yaml. It talks to the API server directly, with the bearer token and
// CA certificates of a service account, so it needs permission to get and
// update the ConfigMap. It never creates it: the ConfigMap must exist, even
// with no state.yaml, before anything is written.
type ConfigMap struct {
	Namespace string
	Name      string
	// APIServer is the API server's URL, such as https://10.96.0.1:443.
	APIServer string
	// TokenFile and CAFile are read for every request: the kubelet rotates
	// the token in place.
	TokenFile string
	CAFile    string
}

// InCluster returns the ConfigMap store for a ConfigMap in the cluster the
// issuer runs in, reached as the pod's service account.
func InCluster(namespace, name string) (*ConfigMap, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("the state is in a ConfigMap, but KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set: the issuer is not running in a Kubernetes pod")
	}
	return &ConfigMap{
		Namespace: namespace,
		Name:      name,
		APIServer: "https://" + net.JoinHostPort(host, port),
		TokenFile: state.ServiceAccountTokenFile,
		CAFile:    state.ServiceAccountCAFile,
	}, nil
}

func (c *ConfigMap) String() string { return "ConfigMap " + c.Namespace + "/" + c.Name }

// configMap is the part of a ConfigMap object the store reads. The whole
// object is kept as it came for updates, so labels, annotations and the
// rest survive them.
type configMap struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Data       map[string]string `json:"data"`
	BinaryData map[string]string `json:"binaryData"`
}

// Load implements Store.
func (c *ConfigMap) Load(ctx context.Context) (*Snapshot, error) {
	obj, _, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return empty(Absent), nil
	}
	version := obj.Metadata.ResourceVersion
	var others []string
	for k := range obj.Data {
		if k != ConfigMapKey {
			others = append(others, k)
		}
	}
	for k := range obj.BinaryData {
		others = append(others, k)
	}
	if len(others) > 0 {
		slices.Sort(others)
		return &Snapshot{Version: version, Problem: fmt.Errorf("%s holds keys other than %s: %s", c, ConfigMapKey, strings.Join(others, ", "))}, nil
	}
	data := obj.Data[ConfigMapKey]
	if strings.TrimSpace(data) == "" {
		return empty(version), nil
	}
	return parsed(version, []byte(data)), nil
}

// ErrNoConfigMap means the ConfigMap to write to does not exist. The store
// does not create it, so the issuer needs no permission to create objects.
var ErrNoConfigMap = errors.New("the ConfigMap does not exist; create it first, for example with kubectl create configmap NAME -n NAMESPACE --from-literal=state.yaml=")

// Write implements Store. The API server enforces the compare-and-swap: an
// update carries the resourceVersion it replaces. Writing with Absent fails,
// with ErrConflict when the ConfigMap exists and ErrNoConfigMap when not.
func (c *ConfigMap) Write(ctx context.Context, st *state.State, ifVersion string) (string, error) {
	st, err := canonical(st)
	if err != nil {
		return "", err
	}
	data, err := encodeYAML(st)
	if err != nil {
		return "", err
	}
	current, raw, err := c.get(ctx)
	if err != nil {
		return "", err
	}
	if current == nil && ifVersion == Absent {
		return "", fmt.Errorf("%s: %w", c, ErrNoConfigMap)
	}
	if current == nil || current.Metadata.ResourceVersion != ifVersion {
		return "", ErrConflict
	}
	metadata, _ := raw["metadata"].(map[string]any)
	if metadata == nil {
		return "", errors.New("the ConfigMap has no metadata")
	}
	metadata["resourceVersion"] = ifVersion
	raw["data"] = map[string]string{ConfigMapKey: string(data)}
	delete(raw, "binaryData")
	return c.send(ctx, http.MethodPut, c.objectURL(), raw)
}

func (c *ConfigMap) collectionURL() string {
	return c.APIServer + "/api/v1/namespaces/" + url.PathEscape(c.Namespace) + "/configmaps"
}

func (c *ConfigMap) objectURL() string {
	return c.collectionURL() + "/" + url.PathEscape(c.Name)
}

// get returns the ConfigMap, or nil when it does not exist.
func (c *ConfigMap) get(ctx context.Context) (*configMap, map[string]any, error) {
	body, status, err := c.do(ctx, http.MethodGet, c.objectURL(), nil)
	if err != nil {
		return nil, nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil, nil
	default:
		return nil, nil, apiError(http.MethodGet, status, body)
	}
	var obj configMap
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", c, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", c, err)
	}
	return &obj, raw, nil
}

// send updates the ConfigMap and returns its new version.
func (c *ConfigMap) send(ctx context.Context, method, target string, obj any) (string, error) {
	payload, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	body, status, err := c.do(ctx, method, target, payload)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusOK, http.StatusCreated:
	case http.StatusConflict:
		return "", ErrConflict
	default:
		return "", apiError(method, status, body)
	}
	var written configMap
	if err := json.Unmarshal(body, &written); err != nil {
		return "", fmt.Errorf("reading the written %s: %w", c, err)
	}
	return written.Metadata.ResourceVersion, nil
}

func (c *ConfigMap) do(ctx context.Context, method, target string, payload []byte) ([]byte, int, error) {
	client, err := c.client()
	if err != nil {
		return nil, 0, err
	}
	defer client.CloseIdleConnections()
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, 0, fmt.Errorf("reading the service account token: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxStoredSize+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxStoredSize {
		return nil, 0, fmt.Errorf("%s %s: the response is too large", method, c)
	}
	return data, resp.StatusCode, nil
}

func (c *ConfigMap) client() (*http.Client, error) {
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading the cluster's CA certificates: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificates", c.CAFile)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// apiError reports a failed request with the API server's message, which
// says what is wrong (a missing permission, for one) and carries nothing
// secret.
func apiError(method string, status int, body []byte) error {
	var st struct {
		Message string `json:"message"`
	}
	msg := http.StatusText(status)
	if json.Unmarshal(body, &st) == nil && st.Message != "" {
		msg = st.Message
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
	}
	return fmt.Errorf("the Kubernetes API answered %s with %d: %s", method, status, msg)
}

package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/state"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issuer.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimal = `
issuer: https://issuer.example.org
trust_domain: example.org
keys_dir: keys
state: { file: state.yaml }
`

func TestLoadDefaults(t *testing.T) {
	path := write(t, minimal)
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if s.KeysDir != filepath.Join(dir, "keys") || s.State.File != filepath.Join(dir, "state.yaml") {
		t.Errorf("relative paths: keys_dir %s, state %s", s.KeysDir, s.State.File)
	}
	if s.TokenTTL != DefaultTokenTTL || s.ActivationDelay != DefaultActivationDelay {
		t.Errorf("token_ttl %s, activation_delay %s", s.TokenTTL, s.ActivationDelay)
	}
	want := VerifierLimits{DefaultVerifiersPerOrigin, DefaultVerifiersTotal, DefaultPerAddressPerMinute, DefaultPerAddressBurst}
	if s.VerifierLimits != want {
		t.Errorf("verifier limits %+v, want %+v", s.VerifierLimits, want)
	}
	defaults := state.DefaultSettings("https://issuer.example.org", s.TrustDomain())
	if strings.Join(s.Validation.ReadableFiles, ",") != strings.Join(defaults.ReadableFiles, ",") ||
		len(s.Validation.BearerTokenFiles) != 1 || len(s.Validation.Verifiers) != 0 {
		t.Errorf("file lists %+v, want the defaults", s.Validation)
	}
	if p := s.Validation.BearerTokenFiles[0].Paths; strings.Join(p, ",") != "/openid/v1/jwks,/.well-known/openid-configuration" {
		t.Errorf("the default bearer token file goes to paths %v", p)
	}
	if s.Management {
		t.Error("the management API is on by default")
	}
	if !s.RefusePrivateAddresses || strings.Join(s.AllowPrivateHosts, ",") != "kubernetes.default.svc.cluster.local:443" {
		t.Errorf("private addresses: refused %v, exempt %v; want refused but for the in-cluster API server", s.RefusePrivateAddresses, s.AllowPrivateHosts)
	}
}

func TestLoadEverything(t *testing.T) {
	s, err := Load(write(t, `
issuer: https://issuer.example.org
trust_domain: example.org
keys_dir: /var/lib/spiffex/keys
token_ttl: 1h
activation_delay: 1h
state:
  configmap: { namespace: spiffex, name: spiffex-state }
management: true
readable_files: [/etc/spiffex/partner-jwks.json]
bearer_token_files:
  - { path: /var/run/secrets/tokens/upstream, hosts: [idp.partner.example, "idp.partner.example:8443"], paths: [/keys] }
verifiers:
  - [/usr/libexec/spiffex/aws-verifier, --region, eu-north-1]
fetch: { refuse_private_addresses: true, allow_private_hosts: [Kubernetes.default.svc.cluster.local, "idp.internal:8443", "[fd00::1]:443", "fd00::2"] }
verifier_user: { uid: 65533, gid: 65533 }
trusted_proxies: [10.0.0.0/8, "2001:db8::1"]
verifier_limits: { per_origin: 2, total: 8, per_address_per_minute: 30, per_address_burst: 5 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.TokenTTL != time.Hour || s.State.ConfigMap.Name != "spiffex-state" || !s.Management || !s.RefusePrivateAddresses {
		t.Errorf("settings = %+v", s)
	}
	if len(s.Validation.ReadableFiles) != 1 || len(s.Validation.Verifiers[0]) != 3 || s.Validation.BearerTokenFiles[0].Hosts[1] != "idp.partner.example:8443" {
		t.Errorf("validation settings = %+v", s.Validation)
	}
	if strings.Join(s.AllowPrivateHosts, ",") != "kubernetes.default.svc.cluster.local:443,idp.internal:8443,[fd00::1]:443,[fd00::2]:443" {
		t.Errorf("allow_private_hosts = %v", s.AllowPrivateHosts)
	}
	if s.VerifierUser == nil || s.VerifierUser.UID != 65533 ||
		len(s.TrustedProxies) != 2 || s.TrustedProxies[1].String() != "2001:db8::1/128" ||
		s.Validation.BearerTokenFiles[0].Paths[0] != "/keys" {
		t.Errorf("settings = %+v", s)
	}
	if s.VerifierLimits != (VerifierLimits{2, 8, 30, 5}) {
		t.Errorf("verifier limits = %+v", s.VerifierLimits)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"unknown field":             minimal + "clients: []\n",
		"no keys_dir":               strings.Replace(minimal, "keys_dir: keys", "", 1),
		"no state":                  strings.Replace(minimal, "state: { file: state.yaml }", "", 1),
		"two state locations":       strings.Replace(minimal, "state: { file: state.yaml }", "state: { file: a, dir: b }", 1),
		"bad configmap name":        strings.Replace(minimal, "state: { file: state.yaml }", "state: { configmap: { namespace: Spiffex, name: x } }", 1),
		"token TTL over an hour":    minimal + "token_ttl: 2h\n",
		"token TTL too short":       minimal + "token_ttl: 1s\n",
		"activation delay tiny":     minimal + "activation_delay: 1s\n",
		"relative readable file":    minimal + "readable_files: [jwks.json]\n",
		"bearer file without host":  minimal + "bearer_token_files: [{ path: /token, hosts: [] }]\n",
		"bearer host with a path":   minimal + "bearer_token_files: [{ path: /token, hosts: [example.org/x] }]\n",
		"relative verifier":         minimal + "verifiers: [[verify]]\n",
		"empty verifier":            minimal + "verifiers: [[]]\n",
		"negative limit":            minimal + "verifier_limits: { total: -1 }\n",
		"per origin over total":     minimal + "verifier_limits: { per_origin: 9, total: 3 }\n",
		"bearer path not a path":    minimal + "bearer_token_files: [{ path: /token, hosts: [h], paths: [keys] }]\n",
		"bad private host":          minimal + "fetch: { allow_private_hosts: [\"a/b\"] }\n",
		"private host port 0":       minimal + "fetch: { allow_private_hosts: [\"a:0\"] }\n",
		"private host bad port":     minimal + "fetch: { allow_private_hosts: [\"a:https\"] }\n",
		"verifier user without gid": minimal + "verifier_user: { uid: 1 }\n",
		"bad trusted proxy":         minimal + "trusted_proxies: [nope]\n",
		"no trust domain":           strings.Replace(minimal, "trust_domain: example.org", "", 1),
		"bad issuer URL":            strings.Replace(minimal, "https://issuer.example.org", "https://issuer.example.org/", 1),
		"two documents":             minimal + "---\nissuer: x\n",
		"empty":                     "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, content)); err == nil {
				t.Error("loaded")
			}
		})
	}
}

// What check and explain read works without the issuer's other settings.
func TestValidationAlone(t *testing.T) {
	f, err := Decode([]byte("issuer: https://issuer.example.org\ntrust_domain: example.org\nreadable_files: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.Validation()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ReadableFiles) != 0 {
		t.Errorf("readable_files: [] kept the defaults: %v", s.ReadableFiles)
	}
}

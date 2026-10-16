package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var chartDir = filepath.Join(repoRoot, "charts", "spiffex")

// helmPath finds helm, skipping the test without it unless
// SPIFFEX_REQUIRE_HELM is set, as it is in CI.
func helmPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("SPIFFEX_REQUIRE_HELM") != "" {
			t.Fatal("helm is required: ", err)
		}
		t.Skip("helm is not installed")
	}
	return path
}

type k8sObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Data  map[string]string `yaml:"data"`
	Rules []struct {
		ResourceNames []string `yaml:"resourceNames"`
		Verbs         []string `yaml:"verbs"`
	} `yaml:"rules"`
}

func helmTemplate(t *testing.T, helm string, args ...string) ([]k8sObject, error) {
	t.Helper()
	cmd := exec.Command(helm, append([]string{"template", "spiffex-issuer", chartDir, "--namespace", "spiffex"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(stderr.String())
	}
	var objects []k8sObject
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o k8sObject
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o.Kind != "" {
			objects = append(objects, o)
		}
	}
	return objects, nil
}

func find(objects []k8sObject, kind, name string) *k8sObject {
	for i, o := range objects {
		if o.Kind == kind && (name == "" || o.Metadata.Name == name) {
			return &objects[i]
		}
	}
	return nil
}

// The chart renders for every value set under charts/spiffex/ci, and the
// settings and state it renders pass spiffex check.
func TestChart(t *testing.T) {
	helm := helmPath(t)
	valueSets, err := filepath.Glob(filepath.Join(chartDir, "ci", "*-values.yaml"))
	if err != nil || len(valueSets) == 0 {
		t.Fatalf("no value sets in %s/ci: %v", chartDir, err)
	}
	for _, values := range valueSets {
		t.Run(filepath.Base(values), func(t *testing.T) {
			objects, err := helmTemplate(t, helm, "-f", values)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkRendered(t, objects); err != nil {
				t.Fatal(err)
			}
			if find(objects, "Deployment", "") == nil || find(objects, "Service", "") == nil ||
				find(objects, "ServiceAccount", "") == nil || find(objects, "RoleBinding", "") == nil {
				t.Error("a Deployment, Service, ServiceAccount or RoleBinding is missing")
			}
		})
	}
}

// checkRendered runs spiffex check on the settings and state the chart
// rendered.
func checkRendered(t *testing.T, objects []k8sObject) error {
	t.Helper()
	dir := t.TempDir()
	cm := find(objects, "ConfigMap", "spiffex-issuer")
	if cm == nil || cm.Data["issuer.yaml"] == "" {
		return errors.New("no settings ConfigMap with issuer.yaml")
	}
	args := []string{"-settings", writeFile(t, dir, "issuer.yaml", cm.Data["issuer.yaml"])}
	if st := find(objects, "ConfigMap", "spiffex-issuer-state"); st != nil {
		if st.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
			return errors.New("the state ConfigMap lacks helm.sh/resource-policy: keep")
		}
		args = append(args, writeFile(t, dir, "state.yaml", st.Data["state.yaml"]))
	} else {
		// spiffex check needs a state; the settings are what is checked here.
		args = append(args, writeFile(t, dir, "state.yaml", "{}\n"))
	}
	out, err := captureStdout(t, func() error { return runCheck(t.Context(), args) })
	if err != nil {
		return fmt.Errorf("spiffex check: %w\n%s", err, out)
	}
	return nil
}

// The chart's choices that the value sets above leave implicit.
func TestChartDetails(t *testing.T) {
	helm := helmPath(t)
	base := []string{"--set", "trustDomain=example.org", "--set", "signingKeys.existingSecret=keys", "--set", "tls.existingSecret=tls"}

	role := func(objects []k8sObject) (names, verbs []string) {
		r := find(objects, "Role", "")
		if r == nil || len(r.Rules) != 1 {
			t.Fatal("want a Role with one rule")
		}
		return r.Rules[0].ResourceNames, r.Rules[0].Verbs
	}
	objects, err := helmTemplate(t, helm, base...)
	if err != nil {
		t.Fatal(err)
	}
	if names, verbs := role(objects); !slices.Equal(names, []string{"spiffex-issuer-state"}) || !slices.Equal(verbs, []string{"get", "update"}) {
		t.Errorf("with management, the Role gives %v on %v", verbs, names)
	}
	objects, err = helmTemplate(t, helm, append(base, "--set", "management=false")...)
	if err != nil {
		t.Fatal(err)
	}
	if _, verbs := role(objects); !slices.Equal(verbs, []string{"get"}) {
		t.Errorf("without management, the Role gives %v", verbs)
	}
	objects, err = helmTemplate(t, helm, append(base, "--set", "state.existingConfigMap=mine")...)
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := role(objects); !slices.Equal(names, []string{"mine"}) || find(objects, "ConfigMap", "spiffex-issuer-state") != nil {
		t.Errorf("with an existing state ConfigMap, the Role names %v, or the chart still makes one", names)
	}
	if find(objects, "ConfigMap", "spiffex-issuer").Data["issuer.yaml"] == "" ||
		!strings.Contains(find(objects, "ConfigMap", "spiffex-issuer").Data["issuer.yaml"], `name: "mine"`) {
		t.Error("the settings do not name the existing state ConfigMap")
	}

	// A zero verifier limit is kept, meaning the default, rather than dropped.
	objects, err = helmTemplate(t, helm, append(base, "--set", "verifierLimits.perOrigin=0", "--set", "verifierLimits.total=8")...)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(objects, "ConfigMap", "spiffex-issuer").Data["issuer.yaml"]; !strings.Contains(got, "verifier_limits:\n  per_origin: 0\n  total: 8\n") {
		t.Errorf("verifier limits rendered as:\n%s", got)
	}
	if err := checkRendered(t, objects); err != nil {
		t.Error(err)
	}

	// The schema cannot know every rule of the settings; spiffex check does.
	objects, err = helmTemplate(t, helm, append(base, "--set", "tokenTTL=2h")...)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRendered(t, objects); err == nil || !strings.Contains(err.Error(), "token_ttl") {
		t.Errorf("a token lifetime of 2h passed spiffex check: %v", err)
	}

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no signing keys", []string{"--set", "trustDomain=example.org", "--set", "tls.existingSecret=tls"}, "signingKeys.existingSecret is required"},
		{"no trust domain", []string{"--set", "signingKeys.existingSecret=keys", "--set", "tls.existingSecret=tls"}, "trustDomain is required"},
		{"no TLS and no issuer", []string{"--set", "trustDomain=example.org", "--set", "signingKeys.existingSecret=keys"}, "issuer is required without TLS"},
		{"an unknown value", append(slices.Clone(base), "--set", "replica=3"), "replica"},
		{"cert-manager without an issuer", append(slices.Clone(base[:4]), "--set", "tls.certManager.enabled=true"), "tls.certManager.issuerRef.name is required"},
		{"a bad digest", append(slices.Clone(base), "--set", "image.digest=latest"), "image.digest"},
		{"a readable file among the keys", append(slices.Clone(base), "--set", "readableFiles={/keys/k.pem}"), "readableFiles.0"},
		{"a bearer token among the TLS files", append(slices.Clone(base), "--set", "bearerTokenFiles[0].path=/tls/tls.key", "--set", "bearerTokenFiles[0].hosts={h}"), "bearerTokenFiles.0.path"},
		{"a private host that is not host:port", append(slices.Clone(base), "--set", "fetch.allowPrivateHosts={https://h}"), "fetch.allowPrivateHosts.0"},
		{"a relative verifier", append(slices.Clone(base), "--set", "verifiers[0]={verifier}"), "verifiers.0.0"},
		{"an upper-case trust domain", append(slices.Clone(base[2:]), "--set", "trustDomain=Example.org"), "trustDomain"},
	} {
		if _, err := helmTemplate(t, helm, c.args...); err == nil || !schemaErrorNames(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
	}
}

// What the value sets render, as text: the image reference, the TLS
// variants and the hardening the plain manifests have.
func TestChartRendering(t *testing.T) {
	helm := helmPath(t)
	render := func(values string) string {
		t.Helper()
		out, err := exec.Command(helm, "template", "spiffex-issuer", chartDir, "--namespace", "spiffex",
			"-f", filepath.Join(chartDir, "ci", values)).Output()
		if err != nil {
			t.Fatalf("%s: %v", values, err)
		}
		return string(out)
	}
	for values, want := range map[string][]string{
		"tls-secret-values.yaml": {
			`image: "ghcr.io/petersr/spiffex:v`, `secretName: "spiffex-issuer-tls"` + "\n            defaultMode: 0440",
			`secretName: "spiffex-signing-keys"` + "\n            defaultMode: 0440", "readOnlyRootFilesystem: true",
			"fsGroup: 65532", "scheme: HTTPS", "kind: PodDisruptionBudget", "port: 443",
		},
		"cert-manager-values.yaml": {
			`image: "ghcr.io/petersr/spiffex@sha256:0123`, "kind: Certificate", `secretName: "spiffex-issuer-tls"`,
			"- spiffex-issuer.spiffex.svc\n", "- spiffex.example.org", `kind: "ClusterIssuer"`, "verbs: [get]",
		},
		"plain-http-values.yaml": {"scheme: HTTP\n", "port: 80", `issuer: "https://spiffex.example.org"`},
	} {
		out := render(values)
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: the output lacks %q", values, w)
			}
		}
		if values == "plain-http-values.yaml" && (strings.Contains(out, "-tls-cert") || strings.Contains(out, "PodDisruptionBudget")) {
			t.Errorf("%s: renders TLS flags or a PodDisruptionBudget", values)
		}
	}
}

// The replicas spread across nodes and zones by default, as a preference
// only, and a list given replaces that default.
func TestChartTopologySpread(t *testing.T) {
	helm := helmPath(t)
	base := []string{"template", "spiffex-issuer", chartDir, "--namespace", "spiffex",
		"--set", "trustDomain=example.org", "--set", "signingKeys.existingSecret=keys", "--set", "tls.existingSecret=tls"}
	spread := func(args ...string) []map[string]any {
		t.Helper()
		out, err := exec.Command(helm, append(slices.Clone(base), args...)...).Output()
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(out))
		for {
			var o struct {
				Kind string `yaml:"kind"`
				Spec struct {
					Template struct {
						Spec struct {
							TopologySpreadConstraints []map[string]any `yaml:"topologySpreadConstraints"`
						} `yaml:"spec"`
					} `yaml:"template"`
				} `yaml:"spec"`
			}
			if err := dec.Decode(&o); err != nil {
				t.Fatal("no Deployment rendered: ", err)
			}
			if o.Kind == "Deployment" {
				return o.Spec.Template.Spec.TopologySpreadConstraints
			}
		}
	}

	got := spread()
	var keys []string
	for _, c := range got {
		keys = append(keys, fmt.Sprint(c["topologyKey"]))
		if c["maxSkew"] != 1 || c["whenUnsatisfiable"] != "ScheduleAnyway" {
			t.Errorf("%v: want maxSkew 1 and whenUnsatisfiable ScheduleAnyway", c)
		}
		want := map[string]any{"matchLabels": map[string]any{
			"app.kubernetes.io/name": "spiffex", "app.kubernetes.io/instance": "spiffex-issuer",
		}}
		if fmt.Sprint(c["labelSelector"]) != fmt.Sprint(want) {
			t.Errorf("%v: the label selector is not the chart's selector labels", c)
		}
	}
	if !slices.Equal(keys, []string{"kubernetes.io/hostname", "topology.kubernetes.io/zone"}) {
		t.Errorf("the default spreads over %v", keys)
	}

	got = spread("--set", "topologySpreadConstraints[0].maxSkew=2", "--set", "topologySpreadConstraints[0].topologyKey=rack",
		"--set", "topologySpreadConstraints[0].whenUnsatisfiable=DoNotSchedule")
	if len(got) != 1 || got[0]["topologyKey"] != "rack" {
		t.Errorf("a list given did not replace the default: %v", got)
	}
}

// schemaErrorNames reports whether a Helm error names the value at path.
// Helm releases word schema errors differently: older ones name the value
// as image.digest, newer ones as the JSON pointer /image/digest.
func schemaErrorNames(msg, path string) bool {
	return strings.Contains(msg, path) || strings.Contains(msg, "/"+strings.ReplaceAll(path, ".", "/"))
}

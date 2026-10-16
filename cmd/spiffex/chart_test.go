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

// renderObjects renders the chart and decodes every object it renders as a
// plain map.
func renderObjects(t *testing.T, helm string, args ...string) ([]map[string]any, error) {
	t.Helper()
	cmd := exec.Command(helm, append([]string{"template", "spiffex-issuer", chartDir, "--namespace", "spiffex"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(stderr.String())
	}
	var objects []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o map[string]any
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o != nil {
			objects = append(objects, o)
		}
	}
	return objects, nil
}

func findObject(objects []map[string]any, kind string) map[string]any {
	for _, o := range objects {
		if o["kind"] == kind {
			return o
		}
	}
	return nil
}

// The Ingress routes every path of its host to the Service, with the TLS
// Secret given, and with no TLS in the pod the issuer URL must be the
// ingress host's.
func TestChartIngress(t *testing.T) {
	helm := helmPath(t)
	values := []string{"-f", filepath.Join(chartDir, "ci", "ingress-values.yaml")}
	objects, err := renderObjects(t, helm, values...)
	if err != nil {
		t.Fatal(err)
	}
	ingress := findObject(objects, "Ingress")
	if ingress == nil {
		t.Fatal("no Ingress rendered")
	}
	var spec struct {
		IngressClassName string `yaml:"ingressClassName"`
		TLS              []struct {
			Hosts      []string `yaml:"hosts"`
			SecretName string   `yaml:"secretName"`
		} `yaml:"tls"`
		Rules []struct {
			Host string `yaml:"host"`
			HTTP struct {
				Paths []struct {
					Path     string `yaml:"path"`
					PathType string `yaml:"pathType"`
					Backend  struct {
						Service struct {
							Name string `yaml:"name"`
							Port struct {
								Number int `yaml:"number"`
							} `yaml:"port"`
						} `yaml:"service"`
					} `yaml:"backend"`
				} `yaml:"paths"`
			} `yaml:"http"`
		} `yaml:"rules"`
	}
	raw, err := yaml.Marshal(ingress["spec"])
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.IngressClassName != "nginx" {
		t.Errorf("ingressClassName is %q", spec.IngressClassName)
	}
	if len(spec.TLS) != 1 || !slices.Equal(spec.TLS[0].Hosts, []string{"spiffex.example.org"}) || spec.TLS[0].SecretName != "spiffex-public-tls" {
		t.Errorf("the tls section is %+v", spec.TLS)
	}
	if len(spec.Rules) != 1 || spec.Rules[0].Host != "spiffex.example.org" || len(spec.Rules[0].HTTP.Paths) != 1 {
		t.Fatalf("the rules are %+v", spec.Rules)
	}
	path := spec.Rules[0].HTTP.Paths[0]
	if path.Path != "/" || path.PathType != "Prefix" || path.Backend.Service.Name != "spiffex-issuer" || path.Backend.Service.Port.Number != 80 {
		t.Errorf("the path is %+v", path)
	}
	annotations, _ := ingress["metadata"].(map[string]any)["annotations"].(map[string]any)
	if annotations["cert-manager.io/cluster-issuer"] != "letsencrypt-prod" {
		t.Errorf("the Ingress's annotations are %v", annotations)
	}
	settings := find(mustObjects(t, helm, values...), "ConfigMap", "spiffex-issuer").Data["issuer.yaml"]
	if !strings.Contains(settings, `issuer: "https://spiffex.example.org"`) || strings.Contains(findObjectText(t, objects, "Deployment"), "-tls-cert") {
		t.Errorf("the issuer is not plain HTTP at the ingress host:\n%s", settings)
	}

	// Without a TLS Secret the Ingress has no tls section; without the
	// ingress there is none at all.
	objects, err = renderObjects(t, helm, append(slices.Clone(values), "--set", "ingress.tls.secretName=")...)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findObject(objects, "Ingress")["spec"].(map[string]any)["tls"]; ok {
		t.Error("an Ingress without a TLS Secret has a tls section")
	}
	objects, err = renderObjects(t, helm, append(slices.Clone(values), "--set", "ingress.enabled=false")...)
	if err != nil {
		t.Fatal(err)
	}
	if findObject(objects, "Ingress") != nil {
		t.Error("an Ingress is rendered with ingress.enabled false")
	}

	// With TLS in the pod as well, ingress-nginx is told to speak HTTPS to
	// the issuer's HTTPS port, unless the annotation is given.
	tlsInPod := append(slices.Clone(values), "--set", "tls.existingSecret=tls")
	objects, err = renderObjects(t, helm, tlsInPod...)
	if err != nil {
		t.Fatal(err)
	}
	text := findObjectText(t, objects, "Ingress")
	if !strings.Contains(text, "nginx.ingress.kubernetes.io/backend-protocol: HTTPS") || !strings.Contains(text, "number: 443") ||
		!strings.Contains(text, "cert-manager.io/cluster-issuer: letsencrypt-prod") {
		t.Errorf("with TLS in the pod, the Ingress is:\n%s", text)
	}
	objects, err = renderObjects(t, helm, append(slices.Clone(tlsInPod), "--set", `ingress.annotations.nginx\.ingress\.kubernetes\.io/backend-protocol=GRPCS`)...)
	if err != nil {
		t.Fatal(err)
	}
	if text := findObjectText(t, objects, "Ingress"); !strings.Contains(text, "backend-protocol: GRPCS") || strings.Contains(text, "backend-protocol: HTTPS") {
		t.Errorf("a backend protocol given was replaced:\n%s", text)
	}
	if text := findObjectText(t, mustRender(t, helm, values...), "Ingress"); strings.Contains(text, "backend-protocol") {
		t.Errorf("without TLS in the pod, the Ingress sets a backend protocol:\n%s", text)
	}

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"another host", []string{"--set", "issuer=https://other.example.org"}, "issuer must be https://spiffex.example.org"},
		{"another host with TLS in the pod", []string{"--set", "tls.existingSecret=tls", "--set", "issuer=https://other.example.org"}, "issuer must be https://spiffex.example.org"},
		{"the Service's URL with TLS in the pod", []string{"--set", "tls.existingSecret=tls", "--set", "issuer="}, "^https://"},
		{"a path on the host", []string{"--set", "issuer=https://spiffex.example.org/spiffex"}, "issuer must be https://spiffex.example.org"},
		{"plain HTTP", []string{"--set", "issuer=http://spiffex.example.org"}, "^https://"},
		{"no issuer", []string{"--set", "issuer="}, "^https://"},
		{"no host", []string{"--set", "ingress.host="}, "ingress.host"},
		{"a wildcard host", []string{"--set", "ingress.host=*.example.org"}, "ingress.host"},
	} {
		if _, err := renderObjects(t, helm, append(slices.Clone(values), c.args...)...); err == nil || !schemaErrorNames(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
	}
}

func mustRender(t *testing.T, helm string, args ...string) []map[string]any {
	t.Helper()
	objects, err := renderObjects(t, helm, args...)
	if err != nil {
		t.Fatal(err)
	}
	return objects
}

func mustObjects(t *testing.T, helm string, args ...string) []k8sObject {
	t.Helper()
	objects, err := helmTemplate(t, helm, args...)
	if err != nil {
		t.Fatal(err)
	}
	return objects
}

func findObjectText(t *testing.T, objects []map[string]any, kind string) string {
	t.Helper()
	out, err := yaml.Marshal(findObject(objects, kind))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// extraObjects are rendered as given, maps and strings alike, with tpl.
func TestChartExtraObjects(t *testing.T) {
	helm := helmPath(t)
	objects, err := renderObjects(t, helm, "-f", filepath.Join(chartDir, "ci", "ingress-values.yaml"),
		"--set-json", `extraObjects[1]="apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ include \"spiffex.fullname\" . }}-extra\n"`)
	if err != nil {
		t.Fatal(err)
	}
	es := findObject(objects, "ExternalSecret")
	if es == nil {
		t.Fatal("no ExternalSecret rendered")
	}
	if md := es["metadata"].(map[string]any); md["name"] != "spiffex-signing-keys" || md["namespace"] != "spiffex" {
		t.Errorf("the ExternalSecret's metadata is %v; tpl did not run", md)
	}
	if !strings.Contains(findObjectText(t, objects, "ExternalSecret"), "target: $1") {
		t.Error("the ExternalSecret's rewrite target was changed")
	}
	extra := false
	for _, o := range objects {
		if o["kind"] == "ServiceAccount" && o["metadata"].(map[string]any)["name"] == "spiffex-issuer-extra" {
			extra = true
		}
	}
	if !extra {
		t.Error("an extra object given as a string was not rendered through tpl")
	}
	// Braces meant for the object itself pass through tpl when escaped, as
	// the README says.
	if escaped := find(mustObjects(t, helm, "-f", filepath.Join(chartDir, "ci", "ingress-values.yaml"),
		"--set-json", `extraObjects[0]={"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "escaped"}, "data": {"template": "{{ \"{{ .password }}\" }}"}}`),
		"ConfigMap", "escaped"); escaped == nil || escaped.Data["template"] != "{{ .password }}" {
		t.Errorf("an escaped template rendered as %+v", escaped)
	}

	// The state ConfigMap takes further annotations and keeps its own: the
	// keep policy always, and Prune=false,Delete=false added to the sync
	// options given, without repeating one already there.
	for _, c := range []struct{ given, want string }{
		{"", "Prune=false,Delete=false"},
		{"ServerSideApply=true", "ServerSideApply=true,Prune=false,Delete=false"},
		{"Delete=false, ServerSideApply=true", "Delete=false,ServerSideApply=true,Prune=false"},
	} {
		args := []string{"--set", "trustDomain=example.org", "--set", "signingKeys.existingSecret=keys", "--set", "tls.existingSecret=tls",
			"--set", "state.configMapAnnotations.helm\\.sh/resource-policy=delete",
			"--set", "state.configMapAnnotations.argocd\\.argoproj\\.io/compare-options=IgnoreExtraneous"}
		if c.given != "" {
			args = append(args, "--set-string", "state.configMapAnnotations.argocd\\.argoproj\\.io/sync-options="+strings.ReplaceAll(c.given, ",", "\\,"))
		}
		st := find(mustObjects(t, helm, args...), "ConfigMap", "spiffex-issuer-state")
		if st == nil || st.Metadata.Annotations["argocd.argoproj.io/compare-options"] != "IgnoreExtraneous" ||
			st.Metadata.Annotations["argocd.argoproj.io/sync-options"] != c.want ||
			st.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
			t.Errorf("sync options %q: the state ConfigMap's annotations are %+v, want sync options %q", c.given, st, c.want)
		}
	}
}

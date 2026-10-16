package store

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// fakeAPIServer serves one namespace's ConfigMaps the way the Kubernetes API
// does: resourceVersions that change on every write, and 409 for a stale
// update or a create of something that exists.
type fakeAPIServer struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	next    int
	token   string
}

func (f *fakeAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const prefix = "/api/v1/namespaces/spiffex/configmaps"
	name, isObject := strings.CutPrefix(r.URL.Path, prefix+"/")
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == http.MethodGet && isObject:
		obj, ok := f.objects[name]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		reply(http.StatusOK, obj)
	case r.Method == http.MethodPost && r.URL.Path == prefix:
		var obj map[string]any
		_ = json.NewDecoder(r.Body).Decode(&obj)
		name := obj["metadata"].(map[string]any)["name"].(string)
		if _, exists := f.objects[name]; exists {
			reply(http.StatusConflict, map[string]string{"message": "already exists"})
			return
		}
		f.store(name, obj)
		reply(http.StatusCreated, obj)
	case r.Method == http.MethodPut && isObject:
		var obj map[string]any
		_ = json.NewDecoder(r.Body).Decode(&obj)
		current, ok := f.objects[name]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		rv := obj["metadata"].(map[string]any)["resourceVersion"]
		if rv != current["metadata"].(map[string]any)["resourceVersion"] {
			reply(http.StatusConflict, map[string]string{"message": "the object has been modified"})
			return
		}
		f.store(name, obj)
		reply(http.StatusOK, obj)
	default:
		reply(http.StatusMethodNotAllowed, map[string]string{"message": "no"})
	}
}

func (f *fakeAPIServer) store(name string, obj map[string]any) {
	f.next++
	obj["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.next)
	f.objects[name] = obj
}

func newConfigMapStore(t *testing.T) (*ConfigMap, *fakeAPIServer) {
	t.Helper()
	api := &fakeAPIServer{objects: map[string]map[string]any{}, token: "s3cret"}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &ConfigMap{Namespace: "spiffex", Name: "spiffex-state", APIServer: srv.URL, TokenFile: token, CAFile: ca}, api
}

func TestConfigMap(t *testing.T) {
	c, _ := newConfigMapStore(t)
	testStoreBasics(t, c)
	t.Run("concurrent writes", func(t *testing.T) {
		c, _ := newConfigMapStore(t)
		testConcurrentWrites(t, c)
	})
}

func TestConfigMapKeepsMetadataAndRefusesOtherKeys(t *testing.T) {
	c, api := newConfigMapStore(t)
	api.objects["spiffex-state"] = map[string]any{
		"metadata": map[string]any{"name": "spiffex-state", "resourceVersion": "41", "labels": map[string]any{"app": "spiffex"}},
		"data":     map[string]any{"state.yaml": ""},
	}
	snap := load(t, c)
	if snap.Version != "41" || len(snap.State.Origins) != 0 {
		t.Fatalf("an empty state.yaml: %+v", snap)
	}
	if _, err := c.Write(context.Background(), sampleState(t), "41"); err != nil {
		t.Fatal(err)
	}
	labels := api.objects["spiffex-state"]["metadata"].(map[string]any)["labels"]
	if labels == nil {
		t.Error("the update dropped the ConfigMap's labels")
	}

	api.objects["spiffex-state"]["data"] = map[string]any{"state.yaml": "", "extra": "x"}
	snap, err := c.Load(context.Background())
	if err != nil || snap.Problem == nil || !strings.Contains(snap.Problem.Error(), "extra") {
		t.Errorf("a ConfigMap with another key: %+v, %v", snap, err)
	}
}

func TestConfigMapErrors(t *testing.T) {
	c, _ := newConfigMapStore(t)
	if err := os.WriteFile(c.TokenFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a refused token: %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InCluster("spiffex", "state"); err == nil {
		t.Error("InCluster worked outside a cluster")
	}
}

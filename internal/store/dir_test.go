package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PeterSR/spiffex/internal/state"
)

func TestDir(t *testing.T) {
	testStoreBasics(t, &Dir{Path: filepath.Join(t.TempDir(), "state")})
	t.Run("concurrent writes", func(t *testing.T) {
		testConcurrentWrites(t, &Dir{Path: filepath.Join(t.TempDir(), "state")})
	})
}

// The tree spreads members over files in the forms the package documents.
func TestDirLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	d := &Dir{Path: root}
	if _, err := d.Write(context.Background(), sampleState(t), Absent); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"origins/kube.yaml", "origins/vms.yaml", "providers/partner.yaml", "grants/operators.yaml",
		"origins/vms/members/billing.pub", "origins/vms/members/orders.jwk", "origins/vms/members/stock.jwk",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
	for _, rel := range []string{"origins/vms/members/mixed.pub", "origins/vms/members/mixed.jwk", "origins/vms/members/odd.pub"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Errorf("%s exists; keys that cannot round-trip through a file belong in the origin's file", rel)
		}
	}
	vms, err := os.ReadFile(filepath.Join(root, "origins/vms.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(vms), "mixed:") || strings.Contains(string(vms), "billing:") {
		t.Errorf("origins/vms.yaml:\n%s", vms)
	}
	if info, err := os.Lstat(root); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the state path is not a link to the tree: %v", err)
	}
}

// A tree written by hand reads as the document it stands for.
func TestDirByHand(t *testing.T) {
	root := t.TempDir()
	key := publicPEM(t)
	files := map[string]string{
		"origins/vms.yaml":                "provider: keys\nmembers:\n  orders:\n    keys:\n      - |\n" + indent(key, "        "),
		"origins/vms/members/billing.pub": key + "\n" + publicPEM(t),
		"origins/vms/members/stock.jwk":   `{"keys": [` + string(publicJWK(t)) + `]}`,
		"origins/kube.yml":                "provider: kubernetes\n",
		"providers/.partner.yaml.swp":     "editor junk",
		".git/HEAD":                       "ref: refs/heads/main\n",
	}
	writeTreeFiles(t, root, files)
	snap := load(t, &Dir{Path: root})
	vms := snap.State.Origins["vms"]
	if vms == nil || len(vms.Members) != 3 || len(vms.Members["billing"].Keys) != 2 || len(vms.Members["stock"].Keys) != 1 {
		t.Fatalf("origin vms = %+v", vms)
	}
	if snap.State.Origins["kube"] == nil {
		t.Error("origin kube from a .yml file is missing")
	}
	report := state.Validate(snap.State, state.DefaultSettings("https://issuer.example.org", td))
	if err := report.Err(); err != nil {
		t.Errorf("the tree is not a valid state: %v", err)
	}
}

func TestDirProblems(t *testing.T) {
	key := publicPEM(t)
	cases := map[string]map[string]string{
		"stray file":                 {"README.md": "hello"},
		"unknown extension":          {"origins/vms.txt": "provider: keys\n"},
		"object given twice":         {"origins/vms.yaml": "provider: keys\n", "origins/vms.json": `{"provider": "keys"}`},
		"members of no origin":       {"origins/vms/members/billing.pub": key},
		"member in file and inline":  {"origins/vms.yaml": "provider: keys\nmembers: { billing: { keys: [x] } }\n", "origins/vms/members/billing.pub": key},
		"member given twice":         {"origins/vms.yaml": "provider: keys\n", "origins/vms/members/billing.pub": key, "origins/vms/members/billing.jwk": string(publicJWK(t))},
		"junk around PEM":            {"origins/vms.yaml": "provider: keys\n", "origins/vms/members/billing.pub": "hello\n" + key},
		"unknown origin subdir":      {"origins/vms.yaml": "provider: keys\n", "origins/vms/keys/a.pub": key},
		"provider directory":         {"providers/partner/x.yaml": "{}"},
		"schema violation":           {"origins/vms.yaml": "provider: keys\nnope: 1\n"},
		"YAML alias":                 {"origins/vms.yaml": "provider: &p keys\nprefix: *p\n"},
		"JWK Set with other members": {"origins/vms.yaml": "provider: keys\n", "origins/vms/members/a.jwk": `{"keys": [], "x": 1}`},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeTreeFiles(t, root, files)
			snap, err := (&Dir{Path: root}).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if snap.Problem == nil {
				t.Errorf("no problem reported; state %+v", snap.State)
			}
		})
	}
}

// A plain directory is replaced by a link to a new tree on the first write,
// and the old content goes.
func TestDirWriteOverPlainDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	writeTreeFiles(t, root, map[string]string{"origins/vms.yaml": "provider: keys\n"})
	d := &Dir{Path: root}
	snap := load(t, d)
	st := snap.State
	st.Origins["ci"] = &state.Origin{Provider: "keys"}
	if _, err := d.Write(context.Background(), st, snap.Version); err != nil {
		t.Fatal(err)
	}
	if got := load(t, d); len(got.State.Origins) != 2 {
		t.Errorf("origins after the write: %v", got.State.Origins)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// The link, its one tree and the lock file; nothing left over.
	if len(names) != 3 {
		t.Errorf("the parent directory holds %v", names)
	}
}

// Readers never see a tree that is being written: every load while writes
// go on returns one of the documents written.
func TestDirReadersSeeWholeTrees(t *testing.T) {
	d := &Dir{Path: filepath.Join(t.TempDir(), "state")}
	ctx := context.Background()
	docs := map[string]bool{}
	var states []*state.State
	for i := range 4 {
		st := &state.State{Origins: map[string]*state.Origin{}}
		for j := 0; j <= i*3; j++ {
			st.Origins["o"+string(rune('a'+j))] = &state.Origin{Provider: "keys"}
		}
		states = append(states, st)
		docs[encoded(t, st)] = true
	}
	version, err := d.Write(ctx, states[0], Absent)
	if err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				snap, err := d.Load(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if snap.Problem != nil || !docs[encoded(t, snap.State)] {
					t.Errorf("a reader saw a state that was never written: %v %v", snap.Problem, snap.State)
					return
				}
			}
		}()
	}
	for i := range 60 {
		if version, err = d.Write(ctx, states[i%len(states)], version); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
}

func writeTreeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return prefix + strings.Join(lines, "\n"+prefix) + "\n"
}

// Members whose files would not read back as themselves stay in the
// origin's file, and the round trip holds.
func TestDirMembersThatStayInline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	d := &Dir{Path: root}
	key := func() *state.Member { return &state.Member{Keys: []json.RawMessage{rawString(publicPEM(t))}} }
	st := &state.State{Origins: map[string]*state.Origin{"vms": {Provider: "keys", Members: map[string]*state.Member{
		".hidden": key(), "Billing": key(), "billing": key(), "orders": key(),
	}}}}
	if _, err := d.Write(context.Background(), st, Absent); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "origins/vms/members"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "orders.pub" {
		t.Errorf("member files: %v, want only orders.pub", entries)
	}
	if got := load(t, d); encoded(t, got.State) != encoded(t, st) {
		t.Error("the round trip changed the document")
	}
}

func TestDirMemberFilesDifferingInCase(t *testing.T) {
	root := t.TempDir()
	writeTreeFiles(t, root, map[string]string{
		"origins/vms.yaml":                "provider: keys\n",
		"origins/vms/members/billing.pub": publicPEM(t),
		"origins/vms/members/Billing.pub": publicPEM(t),
	})
	snap, err := (&Dir{Path: root}).Load(context.Background())
	if err != nil || snap.Problem == nil || !strings.Contains(snap.Problem.Error(), "only in case") {
		t.Errorf("snapshot %+v, %v; want a problem", snap, err)
	}
}

// A tree that does not read back as the document is never put in place:
// the previous state stays, untouched.
func TestDirWriteRefusesAMismatchedTree(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("over a plain directory: %v", plain), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			d := &Dir{Path: root}
			var version string
			if plain {
				writeTreeFiles(t, root, map[string]string{"origins/vms.yaml": "provider: keys\n"})
				version = load(t, d).Version
			} else {
				var err error
				if version, err = d.Write(context.Background(), &state.State{Origins: map[string]*state.Origin{"vms": {Provider: "keys"}}}, Absent); err != nil {
					t.Fatal(err)
				}
			}
			afterWriteTree = func(tree string) {
				writeTreeFiles(t, tree, map[string]string{"origins/extra.yaml": "provider: keys\n"})
			}
			defer func() { afterWriteTree = nil }()
			_, err := d.Write(context.Background(), &state.State{Origins: map[string]*state.Origin{"ci": {Provider: "keys"}}}, version)
			if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("err = %v", err)
			}
			info, err := os.Lstat(root)
			if err != nil || (info.Mode()&os.ModeSymlink != 0) == plain {
				t.Errorf("the state path was swapped: %v", err)
			}
			if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(root), ".state.tree-*")); len(leftovers) > map[bool]int{true: 0, false: 1}[plain] {
				t.Errorf("trees left behind: %v", leftovers)
			}
			snap := load(t, d)
			if snap.Version != version || snap.State.Origins["vms"] == nil || len(snap.State.Origins) != 1 {
				t.Errorf("after the refused write: version %q, origins %v", snap.Version, snap.State.Origins)
			}
		})
	}
}

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
)

// repoRoot is where the examples and docs are, seen from this package.
const repoRoot = "../.."

// The settings documentation snippets are validated with, unless their
// marker names a settings file.
var docSettings = state.DefaultSettings("https://issuer.example.org", spiffeid.RequireTrustDomainFromString("example.org"))

// Every directory under examples/ holds an issuer.yaml, the issuer's
// settings, and state documents that must validate under them.
func TestExamples(t *testing.T) {
	var dirs []string
	err := filepath.WalkDir(filepath.Join(repoRoot, "examples"), func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	documents := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var docs []string
		for _, e := range entries {
			if !e.IsDir() && e.Name() != "issuer.yaml" && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".json")) {
				docs = append(docs, filepath.Join(dir, e.Name()))
			}
		}
		if len(docs) == 0 {
			continue
		}
		settingsFile := filepath.Join(dir, "issuer.yaml")
		s, err := settings.Load(settingsFile)
		if err != nil {
			t.Errorf("%s: %v", settingsFile, err)
			continue
		}
		for _, doc := range docs {
			documents++
			r, err := checkFile(doc, false, s.Validation)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Err(); err != nil {
				t.Errorf("%s: %v", doc, err)
			}
		}
	}
	if documents == 0 {
		t.Error("no state documents found under examples/")
	}
}

// A code block in the documentation is checked when the line before its
// opening fence is a marker:
//
//	<!-- check: settings -->           an issuer settings file
//	<!-- check: state -->              a state document
//	<!-- check: provider NAME -->      one provider
//	<!-- check: origin NAME -->        one origin, using shipped providers
//	<!-- check: file PATH -->          a copy of the file at PATH, relative
//	                                   to the repository root, in any language
//
// A marker may add "invalid", for a block shown because validation refuses
// it, and "settings=PATH", a settings file relative to the repository root
// to validate a state, provider or origin with.
func TestDocumentationExamples(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join(repoRoot, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, filepath.Join(repoRoot, "README.md"))
	checked := 0
	for _, doc := range docs {
		for _, b := range markedBlocks(t, doc) {
			checked++
			checkBlock(t, b)
		}
	}
	if checked == 0 {
		t.Error("no marked code blocks found in the documentation")
	}
}

type markedBlock struct {
	where   string // file:line of the marker
	kind    string
	name    string
	invalid bool
	with    string // settings file, relative to the repository root
	content string
}

func markedBlocks(t *testing.T, path string) []markedBlock {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var blocks []markedBlock
	var current *markedBlock
	var body strings.Builder
	inBlock := false
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		switch {
		case inBlock && strings.TrimSpace(text) == "```":
			inBlock = false
			current.content = body.String()
			blocks = append(blocks, *current)
			current = nil
		case inBlock:
			body.WriteString(text + "\n")
		case current != nil:
			if text != "```yaml" && (current.kind != "file" || !strings.HasPrefix(text, "```")) {
				t.Errorf("%s: the marker is not followed by a code block of its kind", current.where)
				current = nil
				continue
			}
			inBlock = true
			body.Reset()
		case strings.HasPrefix(text, "<!-- check:"):
			fields := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(text, "<!-- check:"), "-->"))
			b := markedBlock{where: path + ":" + strconv.Itoa(line)}
			for i, field := range fields {
				switch {
				case i == 0:
					b.kind = field
				case field == "invalid":
					b.invalid = true
				case strings.HasPrefix(field, "settings="):
					b.with = strings.TrimPrefix(field, "settings=")
				case b.name == "":
					b.name = field
				default:
					t.Errorf("%s: unknown marker field %q", b.where, field)
				}
			}
			current = &b
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if current != nil {
		t.Errorf("%s: the marker is not followed by a code block", current.where)
	}
	return blocks
}

func checkBlock(t *testing.T, b markedBlock) {
	t.Helper()
	dir := t.TempDir()
	s := docSettings
	if b.with != "" {
		f, err := settings.ReadFile(filepath.Join(repoRoot, b.with))
		if err != nil {
			t.Errorf("%s: %v", b.where, err)
			return
		}
		if s, err = f.Validation(); err != nil {
			t.Errorf("%s: %s: %v", b.where, b.with, err)
			return
		}
	}

	var problems error
	switch b.kind {
	case "file":
		want, err := os.ReadFile(filepath.Join(repoRoot, b.name))
		if err != nil {
			t.Errorf("%s: %v", b.where, err)
		} else if string(want) != b.content {
			t.Errorf("%s: the block differs from %s", b.where, b.name)
		}
		return
	case "settings":
		path := writeFile(t, dir, "issuer.yaml", b.content)
		_, problems = settings.Load(path)
	case "state", "provider":
		if (b.kind == "provider") != (b.name != "") {
			t.Errorf("%s: a provider marker names the provider, and only it", b.where)
			return
		}
		path := writeFile(t, dir, b.name+".yaml", b.content)
		r, err := checkFile(path, b.kind == "provider", s)
		if err != nil {
			t.Fatal(err)
		}
		problems = r.Err()
	case "origin":
		if b.name == "" {
			t.Errorf("%s: an origin marker names the origin", b.where)
			return
		}
		r, err := checkOrigin([]string{writeFile(t, dir, b.name+".yaml", b.content)}, s)
		if err != nil {
			t.Fatal(err)
		}
		problems = r.Err()
	default:
		t.Errorf("%s: unknown kind %q", b.where, b.kind)
		return
	}
	switch {
	case b.invalid && problems == nil:
		t.Errorf("%s: marked invalid, but it validates", b.where)
	case !b.invalid && problems != nil:
		t.Errorf("%s: %v", b.where, problems)
	}
}

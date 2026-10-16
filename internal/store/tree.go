package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// treeReader reads a state tree into the document it stands for. Problems
// with the layout or a file's content are collected, for the snapshot;
// failures to read are returned at once.
type treeReader struct {
	root     string
	hash     hash.Hash
	problems []string
	doc      map[string]map[string]any
	// memberFiles maps an origin to its members given as files.
	memberFiles map[string]map[string][]any
}

func readTree(root string) (*Snapshot, error) {
	r := &treeReader{root: root, hash: sha256.New(), doc: map[string]map[string]any{}, memberFiles: map[string]map[string][]any{}}
	if err := r.read(); err != nil {
		return nil, err
	}
	version := hex.EncodeToString(r.hash.Sum(nil))
	if len(r.problems) == 0 {
		r.addMembers()
	}
	if len(r.problems) > 0 {
		return &Snapshot{Version: version, Problem: errors.New(strings.Join(r.problems, "\n"))}, nil
	}
	data, err := json.Marshal(r.doc)
	if err != nil {
		return nil, err
	}
	return parsed(version, data), nil
}

func (r *treeReader) problem(rel, format string, args ...any) {
	r.problems = append(r.problems, rel+": "+fmt.Sprintf(format, args...))
}

// entries lists a directory without the names that start with a dot.
func (r *treeReader) entries(rel string) ([]os.DirEntry, error) {
	all, err := os.ReadDir(filepath.Join(r.root, rel))
	if err != nil {
		return nil, err
	}
	var out []os.DirEntry
	for _, e := range all {
		if !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e)
		}
	}
	return out, nil
}

func (r *treeReader) isDir(rel string) (bool, error) {
	info, err := os.Stat(filepath.Join(r.root, rel))
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// readFile reads a file and adds its name and content to the version.
func (r *treeReader) readFile(rel string) ([]byte, error) {
	data, err := readLimited(filepath.Join(r.root, rel))
	if errors.Is(err, errTooLarge) {
		r.problem(rel, "%v", err)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(r.hash, "%d:%s\n%d:", len(rel), rel, len(data))
	r.hash.Write(data)
	return data, nil
}

func (r *treeReader) read() error {
	top, err := r.entries(".")
	if err != nil {
		return err
	}
	for _, e := range top {
		name := e.Name()
		dir, err := r.isDir(name)
		if err != nil {
			return err
		}
		if !dir || !slices.Contains(sections, name) {
			r.problem(name, "not part of a state tree, which holds only the directories %s", strings.Join(sections, ", "))
			continue
		}
		if err := r.readSection(name); err != nil {
			return err
		}
	}
	return nil
}

func (r *treeReader) readSection(section string) error {
	entries, err := r.entries(section)
	if err != nil {
		return err
	}
	objects := map[string]any{}
	files := map[string]string{}
	for _, e := range entries {
		rel := filepath.Join(section, e.Name())
		dir, err := r.isDir(rel)
		if err != nil {
			return err
		}
		if dir {
			if section != "origins" {
				r.problem(rel, "only origins have directories, for their members")
				continue
			}
			if err := r.readOriginDir(e.Name()); err != nil {
				return err
			}
			continue
		}
		name, ok := objectName(e.Name())
		if !ok {
			r.problem(rel, "want a file ending in %s", strings.Join(objectExtensions, ", "))
			continue
		}
		if other, dup := files[name]; dup {
			r.problem(rel, "%s is given twice, here and in %s", name, other)
			continue
		}
		files[name] = rel
		data, err := r.readFile(rel)
		if err != nil {
			return err
		}
		if data == nil {
			continue
		}
		tree, err := state.DecodeTree(data)
		if err != nil {
			r.problem(rel, "%v", err)
			continue
		}
		objects[name] = tree
	}
	if len(objects) > 0 {
		r.doc[section] = objects
	}
	return nil
}

func objectName(file string) (string, bool) {
	for _, ext := range objectExtensions {
		if name, ok := strings.CutSuffix(file, ext); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

func (r *treeReader) readOriginDir(origin string) error {
	rel := filepath.Join("origins", origin)
	entries, err := r.entries(rel)
	if err != nil {
		return err
	}
	for _, e := range entries {
		sub := filepath.Join(rel, e.Name())
		dir, err := r.isDir(sub)
		if err != nil {
			return err
		}
		if !dir || e.Name() != "members" {
			r.problem(sub, "an origin's directory holds only members")
			continue
		}
		if err := r.readMembers(origin); err != nil {
			return err
		}
	}
	return nil
}

func (r *treeReader) readMembers(origin string) error {
	rel := filepath.Join("origins", origin, "members")
	entries, err := r.entries(rel)
	if err != nil {
		return err
	}
	members := map[string][]any{}
	folded := map[string]string{}
	for _, e := range entries {
		file := filepath.Join(rel, e.Name())
		ext := filepath.Ext(e.Name())
		member := strings.TrimSuffix(e.Name(), ext)
		if (ext != ".pub" && ext != ".jwk") || member == "" {
			r.problem(file, "want a member's keys in a .pub or .jwk file")
			continue
		}
		if dir, err := r.isDir(file); err != nil {
			return err
		} else if dir {
			r.problem(file, "want a file, not a directory")
			continue
		}
		if other, dup := folded[strings.ToLower(member)]; dup {
			r.problem(file, "member %s is given twice, or differs from member %s only in case", member, other)
			continue
		}
		folded[strings.ToLower(member)] = member
		data, err := r.readFile(file)
		if err != nil {
			return err
		}
		if data == nil {
			continue
		}
		var keys []any
		if ext == ".pub" {
			keys, err = pemKeys(data)
		} else {
			keys, err = jwkKeys(data)
		}
		if err != nil {
			r.problem(file, "%v", err)
			continue
		}
		members[member] = keys
	}
	r.memberFiles[origin] = members
	return nil
}

// addMembers puts the members given as files into their origins.
func (r *treeReader) addMembers() {
	origins := r.doc["origins"]
	for _, origin := range sortedNames(r.memberFiles) {
		members := r.memberFiles[origin]
		rel := filepath.Join("origins", origin)
		o, ok := origins[origin].(map[string]any)
		if !ok {
			if _, exists := origins[origin]; !exists {
				r.problem(rel, "there is no origin %s for these members", origin)
			}
			continue
		}
		inline, _ := o["members"].(map[string]any)
		if inline == nil {
			inline = map[string]any{}
		}
		for _, member := range sortedNames(members) {
			keys := members[member]
			if _, dup := inline[member]; dup {
				r.problem(filepath.Join(rel, "members"), "member %s is also given in the origin's file", member)
				continue
			}
			inline[member] = map[string]any{"keys": keys}
		}
		if len(inline) > 0 {
			o["members"] = inline
		}
	}
}

// pemKeys reads a .pub file: one or more PEM blocks and nothing else.
func pemKeys(data []byte) ([]any, error) {
	var keys []any
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN ")) {
			return nil, errors.New("want PEM blocks and nothing else")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("a PEM block is malformed")
		}
		keys = append(keys, string(pem.EncodeToMemory(block)))
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM block found")
	}
	return keys, nil
}

// jwkKeys reads a .jwk file: a JWK, or a JWK Set holding several.
func jwkKeys(data []byte) ([]any, error) {
	tree, err := state.DecodeTree(data)
	if err != nil {
		return nil, err
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, errors.New("want a JWK or a JWK Set")
	}
	set, isSet := obj["keys"]
	if !isSet {
		return []any{obj}, nil
	}
	keys, ok := set.([]any)
	if !ok || len(keys) == 0 || len(obj) != 1 {
		return nil, errors.New("a JWK Set must hold only keys, a non-empty list")
	}
	return keys, nil
}

// pemFile returns the content of a .pub file for keys that are all PEM
// blocks written exactly as reading the file would give them back.
func pemFile(keys []json.RawMessage) ([]byte, bool) {
	var b bytes.Buffer
	for _, raw := range keys {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		block, rest := pem.Decode([]byte(s))
		if block == nil || len(rest) != 0 || string(pem.EncodeToMemory(block)) != s {
			return nil, false
		}
		b.WriteString(s)
	}
	return b.Bytes(), len(keys) > 0
}

func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

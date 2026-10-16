package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// Dir keeps the state as a directory tree, laid out as the package
// documentation describes.
type Dir struct {
	Path string
}

func (d *Dir) String() string { return "directory " + d.Path }

var errMissing = errors.New("the state directory does not exist")

// maxTreeAttempts bounds how often Load starts over because the tree was
// swapped while it read it.
const maxTreeAttempts = 5

// Load implements Store.
func (d *Dir) Load(context.Context) (*Snapshot, error) {
	for range maxTreeAttempts {
		root, err := d.resolve()
		if errors.Is(err, errMissing) {
			// A writer replacing a directory with a link leaves the path
			// missing for a moment; only with no write in progress does a
			// missing path mean an empty state.
			unlock, err := lockShared(d.Path)
			if err != nil {
				return nil, err
			}
			_, err = d.resolve()
			unlock()
			if errors.Is(err, errMissing) {
				return empty(Absent), nil
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		snap, readErr := readTree(root)
		// A writer may have swapped the tree, and removed the one being
		// read, in the meantime; then the read is worthless either way.
		if again, err := d.resolve(); err != nil || again != root {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		return snap, nil
	}
	return nil, fmt.Errorf("%s kept changing while it was read", d.Path)
}

// loadLocked is Load for a writer that holds the lock already.
func (d *Dir) loadLocked() (*Snapshot, error) {
	root, err := d.resolve()
	if errors.Is(err, errMissing) {
		return empty(Absent), nil
	}
	if err != nil {
		return nil, err
	}
	return readTree(root)
}

// resolve returns the directory the configured path leads to.
func (d *Dir) resolve() (string, error) {
	if _, err := os.Lstat(d.Path); errors.Is(err, fs.ErrNotExist) {
		return "", errMissing
	} else if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(d.Path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", d.Path)
	}
	return root, nil
}

// Write implements Store. It builds the new tree beside the configured path
// and then points the path at it with one rename of a symbolic link. A path
// that is a plain directory is moved aside first; readers that find the
// path missing in that moment wait for the lock and look again.
func (d *Dir) Write(_ context.Context, st *state.State, ifVersion string) (string, error) {
	st, err := canonical(st)
	if err != nil {
		return "", err
	}
	parent, base := filepath.Split(d.Path)
	parent = filepath.Clean(parent)
	tree, err := os.MkdirTemp(parent, "."+base+".tree-*")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(tree)
		}
	}()
	if err := os.Chmod(tree, 0o755); err != nil {
		return "", err
	}
	if err := writeTree(tree, st); err != nil {
		return "", err
	}
	if afterWriteTree != nil {
		afterWriteTree(tree)
	}
	// What is put in place must read back as exactly the document, and is
	// checked before anyone can see it.
	written, err := readTree(tree)
	if err != nil {
		return "", err
	}
	if written.Problem != nil || !sameDocument(written.State, st) {
		return "", errors.New("the tree written does not read back as the state; nothing was changed")
	}

	unlock, err := lockExclusive(d.Path)
	if err != nil {
		return "", err
	}
	defer unlock()
	current, err := d.loadLocked()
	if err != nil {
		return "", err
	}
	if current.Version != ifVersion {
		return "", ErrConflict
	}
	committed, err := d.swap(parent, base, tree)
	// Once the path points at the tree, the tree is live whatever else
	// failed, and must not be removed.
	keep = committed
	if err != nil {
		return "", err
	}
	return written.Version, nil
}

// afterWriteTree, when set by a test, runs between writing a tree and
// checking it.
var afterWriteTree func(tree string)

func sameDocument(a, b *state.State) bool {
	ea, errA := json.Marshal(a)
	eb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ea) == string(eb)
}

// swap points the configured path at tree, and removes the tree it pointed
// at before when that one was written here or moved aside. committed reports
// whether the path points at tree, which it can do even when err is set.
func (d *Dir) swap(parent, base, tree string) (committed bool, err error) {
	link := filepath.Join(parent, "."+base+".link-"+rand.Text())
	if err := os.Symlink(filepath.Base(tree), link); err != nil {
		return false, err
	}
	defer os.Remove(link)

	var old string
	movedAside := false
	info, err := os.Lstat(d.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return false, err
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(d.Path)
		if err != nil {
			return false, err
		}
		// Only a tree written here is removed; a link the operator made
		// to a directory of their own leaves that directory alone.
		if !strings.Contains(target, "/") && strings.HasPrefix(target, "."+base+".tree-") {
			old = filepath.Join(parent, target)
		}
	case info.IsDir():
		old = filepath.Join(parent, "."+base+".old-"+rand.Text())
		if err := os.Rename(d.Path, old); err != nil {
			return false, err
		}
		movedAside = true
	default:
		return false, fmt.Errorf("%s is not a directory", d.Path)
	}
	if err := os.Rename(link, d.Path); err != nil {
		if movedAside {
			_ = os.Rename(old, d.Path)
		}
		return false, err
	}
	if old != "" {
		os.RemoveAll(old)
	}
	if err := syncDir(parent); err != nil {
		return true, fmt.Errorf("the new state is in place but may not survive a crash: %w", err)
	}
	return true, nil
}

// The kinds of object, each a directory of the tree and a map of the
// document.
var sections = []string{"origins", "providers", "grants"}

var objectExtensions = []string{".yaml", ".yml", ".json"}

func writeTree(root string, st *state.State) error {
	for _, section := range sections {
		if err := os.Mkdir(filepath.Join(root, section), 0o755); err != nil {
			return err
		}
	}
	for name, o := range st.Origins {
		inline := *o
		inline.Members = nil
		folded := map[string]int{}
		for member := range o.Members {
			folded[strings.ToLower(member)]++
		}
		for member, m := range o.Members {
			data, ext, ok := memberFile(m)
			// A member file must read back as this member: not hidden by a
			// leading dot, and not mistaken for another member on a file
			// system that ignores case.
			if strings.HasPrefix(member, ".") || folded[strings.ToLower(member)] > 1 {
				ok = false
			}
			if !ok {
				if inline.Members == nil {
					inline.Members = map[string]*state.Member{}
				}
				inline.Members[member] = m
				continue
			}
			dir := filepath.Join(root, "origins", name, "members")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, member+ext), data, 0o644); err != nil {
				return err
			}
		}
		if err := writeObject(root, "origins", name, &inline); err != nil {
			return err
		}
	}
	for name, p := range st.Providers {
		if err := writeObject(root, "providers", name, p); err != nil {
			return err
		}
	}
	for name, g := range st.Grants {
		if err := writeObject(root, "grants", name, g); err != nil {
			return err
		}
	}
	return nil
}

func writeObject(root, section, name string, v any) error {
	data, err := encodeYAML(v)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, section, name+".yaml"), data, 0o644)
}

// memberFile returns the file a member's keys are written to: a .pub file
// when every key is a PEM block exactly as it would be read back, a .jwk
// file when every key is a JWK, and nothing otherwise, in which case the
// member stays in its origin's file.
func memberFile(m *state.Member) ([]byte, string, bool) {
	if len(m.Keys) == 0 {
		return nil, "", false
	}
	if data, ok := pemFile(m.Keys); ok {
		return data, ".pub", true
	}
	var jwks []json.RawMessage
	for _, raw := range m.Keys {
		if len(raw) == 0 || raw[0] != '{' {
			return nil, "", false
		}
		jwks = append(jwks, raw)
	}
	var v any = jwks[0]
	if len(jwks) > 1 {
		v = map[string]any{"keys": jwks}
	}
	data, err := encodeJSON(v)
	if err != nil {
		return nil, "", false
	}
	return data, ".jwk", true
}

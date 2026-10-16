package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// File keeps the state as one YAML or JSON document. A file ending in .json
// is written as JSON, any other as YAML. An empty file is the empty state.
type File struct {
	Path string
}

func (f *File) String() string { return "file " + f.Path }

// Load implements Store.
func (f *File) Load(context.Context) (*Snapshot, error) {
	data, err := readLimited(f.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return empty(Absent), nil
	case errors.Is(err, errTooLarge):
		return &Snapshot{Version: "too-large", Problem: fmt.Errorf("%s is %w", f.Path, err)}, nil
	case err != nil:
		return nil, err
	}
	version := contentVersion(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return empty(version), nil
	}
	return parsed(version, data), nil
}

// Write implements Store.
func (f *File) Write(_ context.Context, st *state.State, ifVersion string) (string, error) {
	st, err := canonical(st)
	if err != nil {
		return "", err
	}
	var data []byte
	if strings.EqualFold(filepath.Ext(f.Path), ".json") {
		data, err = encodeJSON(st)
	} else {
		data, err = encodeYAML(st)
	}
	if err != nil {
		return "", err
	}
	unlock, err := lockExclusive(f.Path)
	if err != nil {
		return "", err
	}
	defer unlock()

	perm := fs.FileMode(0o644)
	current, err := os.ReadFile(f.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if ifVersion != Absent {
			return "", ErrConflict
		}
	case err != nil:
		return "", err
	default:
		if ifVersion == Absent || contentVersion(current) != ifVersion {
			return "", ErrConflict
		}
		if info, err := os.Stat(f.Path); err == nil {
			perm = info.Mode().Perm()
		}
	}
	if err := writeAtomic(f.Path, data, perm); err != nil {
		return "", err
	}
	return contentVersion(data), nil
}

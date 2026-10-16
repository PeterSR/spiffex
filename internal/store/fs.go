package store

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// lockPath is the lock file writers of the state at path hold, next to it.
// Readers never need it, except to tell a tree that is missing from one
// that is being swapped.
func lockPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
}

// lockExclusive takes the write lock for the state at path. Locks are
// advisory and per open file, so they exclude other processes and other
// writers in this one alike.
func lockExclusive(path string) (unlock func(), err error) {
	f, err := os.OpenFile(lockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return lockFile(f, syscall.LOCK_EX)
}

// lockShared waits until no write to the state at path is in progress and
// holds writers off until unlock. When there is no lock file, no writer has
// ever used it, and nothing is locked.
func lockShared(path string) (unlock func(), err error) {
	f, err := os.Open(lockPath(path))
	if errors.Is(err, fs.ErrNotExist) {
		return func() {}, nil
	}
	if err != nil {
		return nil, err
	}
	return lockFile(f, syscall.LOCK_SH)
}

func lockFile(f *os.File, how int) (func(), error) {
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, how)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, err
		}
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		f.Close()
	}, nil
}

// readLimited reads a file of at most maxStoredSize bytes.
func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStoredSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStoredSize {
		return nil, errTooLarge
	}
	return data, nil
}

var errTooLarge = errors.New("larger than a state document can be")

// writeAtomic replaces path with data by writing a temporary file beside it
// and renaming it into place, so a reader sees the old content or the new,
// never part of either.
func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

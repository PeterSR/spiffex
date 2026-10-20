// Package secretperm tells whether a user could read a secret file, such as
// a signing key, judged by the file's owner, mode bits and POSIX ACLs. It
// keeps an exec verifier's user from the issuer's keys.
package secretperm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// User is the user a check is for. It runs without supplementary groups, so
// its own gid is the only group that counts.
type User struct {
	UID uint32
	GID uint32
}

// CheckFiles refuses when u could read any file in keysDir, apart from
// hidden entries and directories, or any of the other files, or when a
// default ACL on keysDir would let it read files added there later.
func CheckFiles(u User, keysDir string, others ...string) error {
	return checkFiles(u, keysDir, func(string) bool { return true }, others...)
}

// CheckFilesWithSuffix is CheckFiles for a directory that also holds files
// meant to be public, such as certificates: only the files whose names end in
// suffix are judged.
func CheckFilesWithSuffix(u User, dir, suffix string, others ...string) error {
	return checkFiles(u, dir, func(name string) bool { return strings.HasSuffix(name, suffix) }, others...)
}

func checkFiles(u User, keysDir string, judged func(name string) bool, others ...string) error {
	if why, err := DefaultReadable(u, keysDir); err != nil {
		return err
	} else if why != "" {
		return fmt.Errorf("%s: %s, which the verifier user %d:%d could use", keysDir, why, u.UID, u.GID)
	}
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		// Hidden entries are not keys: a Kubernetes Secret mount keeps its
		// ..data links there.
		if !strings.HasPrefix(e.Name(), ".") && judged(e.Name()) {
			files = append(files, filepath.Join(keysDir, e.Name()))
		}
	}
	for _, path := range append(files, others...) {
		if info, err := os.Stat(path); err != nil {
			return err
		} else if info.IsDir() {
			continue
		}
		if err := Check(u, path); err != nil {
			return err
		}
	}
	return nil
}

// Check refuses when u could read the file at path.
func Check(u User, path string) error {
	why, err := Readable(u, path)
	if err != nil {
		return err
	}
	if why != "" {
		return fmt.Errorf("%s is readable by the verifier user %d:%d (%s); a verifier could read it and sign as the issuer", path, u.UID, u.GID, why)
	}
	return nil
}

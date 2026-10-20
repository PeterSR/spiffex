package secretperm

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func writeKey(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadableByModeBits(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	stranger := User{UID: uid + 1000, GID: gid + 1000}
	cases := []struct {
		name     string
		u        User
		mode     os.FileMode
		readable bool
	}{
		{"owner only, verifier a stranger", stranger, 0o600, false},
		{"group readable, verifier in another group", stranger, 0o640, false},
		{"readable by everyone", stranger, 0o644, true},
		{"verifier is the owner", User{uid, gid + 1000}, 0o400, true},
		{"verifier is in the group", User{uid + 1000, gid}, 0o440, true},
		{"verifier is root", User{0, 0}, 0o000, true},
	}
	for _, c := range cases {
		path := writeKey(t, t.TempDir(), "key", c.mode)
		why, err := Readable(c.u, path)
		if err != nil {
			t.Fatal(err)
		}
		if (why != "") != c.readable {
			t.Errorf("%s: %q", c.name, why)
		}
	}
}

func aclBytes(entries ...aclEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, aclVersion)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

const undefinedID = ^uint32(0)

// setACL sets an ACL, or skips the test where the file system has none.
func setACL(t *testing.T, path, name string, entries ...aclEntry) {
	t.Helper()
	err := unix.Setxattr(path, name, aclBytes(entries...), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("the file system of %s has no POSIX ACLs", path)
	}
	if err != nil {
		t.Fatalf("setting %s on %s: %v", name, path, err)
	}
}

// With an ACL, the mode's group bits are its mask, and a user the ACL names
// can read a file whose mode looks private.
func TestReadableThroughAnACL(t *testing.T) {
	uid := uint32(os.Getuid())
	verifier := User{UID: uid + 1000, GID: uint32(os.Getgid()) + 1000}
	dir := t.TempDir()

	path := writeKey(t, dir, "named", 0o600)
	setACL(t, path, "system.posix_acl_access",
		aclEntry{aclUserObj, 6, undefinedID}, aclEntry{aclUser, aclRead, uid},
		aclEntry{aclGroupObj, 0, undefinedID}, aclEntry{aclMask, aclRead, undefinedID}, aclEntry{aclOther, 0, undefinedID})
	if why, err := Readable(verifier, path); err != nil || why == "" {
		t.Errorf("a file with an ACL naming a reader: %q, %v; want it refused", why, err)
	}
	if err := CheckFiles(verifier, dir); err == nil {
		t.Error("CheckFiles accepted a key with an ACL naming a reader")
	}

	masked := writeKey(t, t.TempDir(), "masked", 0o600)
	setACL(t, masked, "system.posix_acl_access",
		aclEntry{aclUserObj, 6, undefinedID}, aclEntry{aclUser, aclRead, uid},
		aclEntry{aclGroupObj, 0, undefinedID}, aclEntry{aclMask, 0, undefinedID}, aclEntry{aclOther, 0, undefinedID})
	if why, err := Readable(verifier, masked); err != nil || why != "" {
		t.Errorf("a file whose ACL mask grants nothing: %q, %v; want it accepted", why, err)
	}
}

// A default ACL on the keys directory reaches keys added later.
func TestDefaultACLOnTheKeysDirectory(t *testing.T) {
	uid := uint32(os.Getuid())
	verifier := User{UID: uid + 1000, GID: uint32(os.Getgid()) + 1000}

	open := t.TempDir()
	setACL(t, open, "system.posix_acl_default",
		aclEntry{aclUserObj, 7, undefinedID}, aclEntry{aclUser, aclRead, uid},
		aclEntry{aclGroupObj, 0, undefinedID}, aclEntry{aclMask, aclRead, undefinedID}, aclEntry{aclOther, 0, undefinedID})
	if err := CheckFiles(verifier, open); err == nil {
		t.Error("CheckFiles accepted a keys directory whose default ACL names a reader")
	}

	closed := t.TempDir()
	setACL(t, closed, "system.posix_acl_default",
		aclEntry{aclUserObj, 7, undefinedID}, aclEntry{aclGroupObj, 0, undefinedID}, aclEntry{aclOther, 0, undefinedID})
	writeKey(t, closed, "key", 0o600)
	if err := CheckFiles(verifier, closed); err != nil {
		t.Errorf("a private default ACL: %v", err)
	}

	everyone := t.TempDir()
	setACL(t, everyone, "system.posix_acl_default",
		aclEntry{aclUserObj, 7, undefinedID}, aclEntry{aclGroupObj, 0, undefinedID}, aclEntry{aclOther, aclRead, undefinedID})
	if err := CheckFiles(verifier, everyone); err == nil {
		t.Error("CheckFiles accepted a default ACL that lets everyone read")
	}
}

func TestCheckFilesSkipsHiddenEntries(t *testing.T) {
	verifier := User{UID: uint32(os.Getuid()) + 1000, GID: uint32(os.Getgid()) + 1000}
	dir := t.TempDir()
	writeKey(t, dir, "key", 0o600)
	writeKey(t, dir, "..data", 0o644)
	tls := writeKey(t, t.TempDir(), "tls.key", 0o604)
	if err := CheckFiles(verifier, dir); err != nil {
		t.Errorf("hidden entries were judged: %v", err)
	}
	if err := CheckFiles(verifier, dir, tls); err == nil {
		t.Error("a TLS key readable by everyone was accepted")
	}
}

// A directory that holds public certificates beside private keys is judged
// by its keys alone.
func TestCheckFilesWithSuffixJudgesOnlyThoseFiles(t *testing.T) {
	verifier := User{UID: uint32(os.Getuid()) + 1000, GID: uint32(os.Getgid()) + 1000}
	dir := t.TempDir()
	writeKey(t, dir, "ca-1.key", 0o600)
	writeKey(t, dir, "ca-1.crt", 0o644)
	if err := CheckFilesWithSuffix(verifier, dir, ".key"); err != nil {
		t.Errorf("a public certificate was judged: %v", err)
	}
	if err := CheckFiles(verifier, dir); err == nil {
		t.Error("CheckFiles should judge every file")
	}
	writeKey(t, dir, "ca-2.key", 0o640)
	if err := CheckFilesWithSuffix(verifier, dir, ".key"); err != nil {
		t.Errorf("a key readable by a group the user is not in: %v", err)
	}
	writeKey(t, dir, "ca-3.key", 0o644)
	if err := CheckFilesWithSuffix(verifier, dir, ".key"); err == nil {
		t.Error("a key readable by everyone was accepted")
	}
}

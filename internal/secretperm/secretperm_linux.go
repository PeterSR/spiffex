package secretperm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// POSIX ACL entry tags, as the kernel stores them in the
// system.posix_acl_access and system.posix_acl_default attributes.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
	aclVersion  = 2
	aclRead     = 4
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// readACL returns the ACL stored in attribute name of path, or nil when there
// is none or the file system has no ACLs.
func readACL(path, name string) ([]aclEntry, error) {
	buf := make([]byte, 4096)
	n, err := unix.Getxattr(path, name, buf)
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return nil, nil
	case errors.Is(err, unix.ERANGE):
		return nil, fmt.Errorf("%s: the ACL is too large to judge", path)
	case err != nil:
		return nil, fmt.Errorf("%s: reading its ACL: %w", path, err)
	}
	buf = buf[:n]
	if len(buf) < 4 || binary.LittleEndian.Uint32(buf) != aclVersion || (len(buf)-4)%8 != 0 {
		return nil, fmt.Errorf("%s: an ACL of a format this check does not know", path)
	}
	var entries []aclEntry
	for b := buf[4:]; len(b) > 0; b = b[8:] {
		entries = append(entries, aclEntry{binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])})
	}
	return entries, nil
}

func extended(entries []aclEntry) bool {
	for _, e := range entries {
		if e.tag == aclUser || e.tag == aclGroup || e.tag == aclMask {
			return true
		}
	}
	return false
}

// Readable returns a reason when u could read the file at path, following
// symbolic links, and "" when it could not. With an extended ACL the mode's
// group bits are the ACL's mask, and any user or group the ACL names may
// read through it, so such a file counts as readable unless the mask grants
// nothing.
func Readable(u User, path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot tell who may read it", path)
	}
	perm := uint32(info.Mode().Perm())
	switch {
	case u.UID == 0:
		return "the user is root", nil
	case st.Uid == u.UID && perm&0o400 != 0:
		return fmt.Sprintf("the user owns it and its mode is %04o", perm), nil
	case st.Gid == u.GID && perm&0o040 != 0:
		return fmt.Sprintf("the user's group owns it and its mode is %04o", perm), nil
	case perm&0o004 != 0:
		return fmt.Sprintf("its mode is %04o", perm), nil
	}
	acl, err := readACL(path, "system.posix_acl_access")
	if err != nil {
		return "", err
	}
	if extended(acl) && perm&0o070 != 0 {
		return fmt.Sprintf("it has an ACL whose mask is %o", perm>>3&7), nil
	}
	return "", nil
}

// DefaultReadable returns a reason when files created in dir would inherit a
// default ACL that could let u read them, and "" otherwise.
func DefaultReadable(u User, dir string) (string, error) {
	acl, err := readACL(dir, "system.posix_acl_default")
	if err != nil || acl == nil {
		return "", err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot tell who may read it", dir)
	}
	mask := uint16(aclRead)
	for _, e := range acl {
		if e.tag == aclMask {
			mask = e.perm
		}
	}
	var granted []string
	for _, e := range acl {
		read := e.perm&aclRead != 0
		switch {
		case e.tag == aclOther && read:
			granted = append(granted, "everyone")
		case (e.tag == aclUser || e.tag == aclGroup) && read && mask&aclRead != 0:
			granted = append(granted, "named users or groups")
		case e.tag == aclGroupObj && read && mask&aclRead != 0 && st.Gid == u.GID:
			granted = append(granted, "the user's group")
		}
	}
	if len(granted) > 0 {
		return "its default ACL lets " + strings.Join(granted, " and ") + " read new files", nil
	}
	return "", nil
}

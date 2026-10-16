//go:build !linux

package secretperm

import "errors"

var errUnsupported = errors.New("judging who may read a file is supported on Linux only")

// Readable fails: only Linux is supported.
func Readable(User, string) (string, error) { return "", errUnsupported }

// DefaultReadable fails: only Linux is supported.
func DefaultReadable(User, string) (string, error) { return "", errUnsupported }

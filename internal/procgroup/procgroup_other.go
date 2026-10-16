//go:build !linux

package procgroup

import "errors"

// awaitExit cannot wait without reaping here, so the group is killed after
// its leader has been reaped.
func awaitExit(int) bool { return false }

func setSubreaper() error {
	return errors.New("child subreapers are a Linux feature")
}

func exitedChildren() []int { return nil }

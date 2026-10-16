package verifier

import (
	"os"
	"strconv"
	"sync"
	"syscall"
)

// closeInheritedOnExec marks every file descriptor above standard error
// close-on-exec. Go opens its own files that way, but descriptors the issuer
// inherited from whatever started it are not, and a verifier must start
// with standard input, output and error only (SPEC section 5.4).
var closeInheritedOnExec = sync.OnceFunc(func() {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
				syscall.CloseOnExec(fd)
			}
		}
		return
	}
})

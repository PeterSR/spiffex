package agent

import (
	"fmt"
	"os"
	"testing"

	"github.com/PeterSR/spiffex/internal/procgroup"
)

// As the agent does when it runs a subject token command, so that what a
// command leaves behind is reaped here and not left to whatever process
// is init, which in a sandbox is the go command.
func TestMain(m *testing.M) {
	if err := procgroup.BecomeSubreaper(); err != nil {
		fmt.Fprintln(os.Stderr, "not a subreaper:", err)
	}
	os.Exit(m.Run())
}

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/proctest"
)

func TestSubjectTokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  header.payload.sig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := SubjectToken{File: path}.grantParams("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if params.Get("subject_token") != "header.payload.sig" || params.Get("subject_token_type") != tokenTypeJWT || params.Has("origin") {
		t.Errorf("params = %v", params)
	}
}

func TestSubjectTokenFromCommand(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run commands with")
	}
	cred := SubjectToken{Command: []string{sh, "-c", `printf 'signed request for %s\n' "$SPIFFEX_TEST_WHO"`}, Origin: "aws"}
	t.Setenv("SPIFFEX_TEST_WHO", "billing")
	params, err := cred.grantParams("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if params.Get("subject_token") != "signed request for billing" || params.Get("subject_token_type") != tokenTypeExec || params.Get("origin") != "aws" {
		t.Errorf("params = %v", params)
	}

	for name, script := range map[string]string{
		"fails":       "echo no credentials >&2; exit 1",
		"prints none": "true",
		"prints much": "head -c 20000 /dev/zero | tr '\\0' a",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := SubjectToken{Command: []string{sh, "-c", script}}.grantParams("", time.Now())
			if err == nil {
				t.Fatal("no error")
			}
			if name == "fails" && !strings.Contains(err.Error(), "no credentials") {
				t.Errorf("err = %v, want the command's standard error in it", err)
			}
		})
	}
}

// What the command leaves running goes when it finishes.
func TestSubjectTokenCommandLeavesNothing(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run commands with")
	}
	pidFile := filepath.Join(t.TempDir(), "pid")
	// The command waits until the test watches its background process.
	script := `sleep 60 & echo $! > "$0"; while [ ! -e "$0.ack" ]; do sleep 0.01; done; echo token`
	done := make(chan error, 1)
	go func() {
		_, err := (SubjectToken{Command: []string{sh, "-c", script, pidFile}}).grantParams("", time.Now())
		done <- err
	}()
	sleeper := proctest.Open(t, proctest.WaitForPID(t, pidFile, 5*time.Second), "sleep")
	proctest.Ack(t, pidFile+".ack")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sleeper.WaitGone(t, 5*time.Second, "the command's background process")
}

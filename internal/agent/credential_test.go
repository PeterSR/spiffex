package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
	script := `sleep 60 & echo $! > "$0"; echo token`
	if _, err := (SubjectToken{Command: []string{sh, "-c", script, pidFile}}).grantParams("", time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	// Signalling 0 or -1 would reach this process's group, or every process
	// the user owns.
	if err != nil || pid <= 1 {
		t.Fatalf("not a child's process ID: %q", data)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the command's background process outlived it")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

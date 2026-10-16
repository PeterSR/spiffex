package state

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Problem is one reason a document is invalid.
type Problem struct {
	// Path locates the problem in the document, such as
	// origins.kube.with.namespaces. It is empty for the document as a whole.
	Path    string
	Message string
	// Closure is set when the problem is a gap in grant closure (SPEC
	// section 8.2), for callers that must say less than Message does to
	// someone who may not read every grant involved.
	Closure *ClosureGap
}

// ClosureGap is one way a set of grants fails to be closed: grant Writer
// gives write on Scope, which reaches the who of grant Reached, but no single
// grant whose who covers Writer's gives Perm on On, a scope of Reached.
type ClosureGap struct {
	Writer  string
	Scope   string
	Reached string
	Perm    string
	On      string
}

func (p Problem) String() string {
	if p.Path == "" {
		return p.Message
	}
	return p.Path + ": " + p.Message
}

// Problems is a list of problems. As an error, it reads as one per line.
type Problems []Problem

func (ps Problems) Error() string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

var plainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// field extends a path with an object member. Members that would read
// ambiguously, claim paths with dots among them, are quoted.
func field(path, name string) string {
	if !plainKey.MatchString(name) {
		return path + "[" + strconv.Quote(name) + "]"
	}
	if path == "" {
		return name
	}
	return path + "." + name
}

// index extends a path with a list element.
func index(path string, i int) string {
	return fmt.Sprintf("%s[%d]", path, i)
}

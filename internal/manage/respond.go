package manage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// apiError is a refusal, answered with its status and a JSON body:
//
//	{"error": "...", "problems": [{"path": "...", "message": "..."}]}
type apiError struct {
	status   int
	msg      string
	problems state.Problems
}

func (e *apiError) Error() string { return e.msg }

func errorf(status int, format string, args ...any) *apiError {
	return &apiError{status: status, msg: fmt.Sprintf(format, args...)}
}

// ErrorBody is the body of every answer that is not a success.
type ErrorBody struct {
	Error    string    `json:"error"`
	Problems []Problem `json:"problems,omitempty"`
}

// Problem is one reason a change would make the state invalid.
type Problem struct {
	// Path locates the problem in the state document, such as
	// origins.web.prefix; it is empty for the document as a whole.
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// CheckResult is the answer to POST /manage/check.
type CheckResult struct {
	Valid    bool      `json:"valid"`
	Problems []Problem `json:"problems,omitempty"`
	// Overrides names the providers that take the place of shipped ones.
	Overrides []string `json:"overrides,omitempty"`
}

func toProblems(ps state.Problems) []Problem {
	out := make([]Problem, len(ps))
	for i, p := range ps {
		out[i] = Problem{Path: p.Path, Message: p.Message}
	}
	return out
}

func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{status: http.StatusInternalServerError, msg: "internal error"}
	}
	if ae.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, ae.status, "", ErrorBody{Error: ae.msg, Problems: toProblems(ae.problems)})
}

// writeJSON answers with a JSON body, and with the state's version as the
// ETag when version is set.
func writeJSON(w http.ResponseWriter, status int, version string, v any) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error": "internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if version != noVersion {
		w.Header().Set("ETag", etag(version))
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// noVersion marks an answer that carries no ETag. Every real version, the
// empty one of a state not stored yet included, gets one.
const noVersion = "\x00"

func etag(version string) string { return `"` + version + `"` }

// ifMatch reports whether version satisfies the request's If-Match header:
// one of its strong entity tags names it, or it is *, which matches any
// state that exists. A state not stored yet has the empty version.
func ifMatch(r *http.Request, version string) bool {
	for _, v := range r.Header.Values("If-Match") {
		for _, tag := range strings.Split(v, ",") {
			tag = strings.TrimSpace(tag)
			if tag == "*" && version != "" || tag == etag(version) {
				return true
			}
		}
	}
	return false
}

// readBody reads a JSON request body of at most MaxBody bytes into v,
// refusing unknown fields and anything after the value.
func readBody(w http.ResponseWriter, r *http.Request, v any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return errorf(http.StatusRequestEntityTooLarge, "the body is larger than %d bytes", MaxBody)
	case err != nil:
		return errorf(http.StatusBadRequest, "reading the body: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errorf(http.StatusBadRequest, "the body is not a valid JSON document of the expected shape: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errorf(http.StatusBadRequest, "the body holds more than one JSON value")
	}
	return nil
}

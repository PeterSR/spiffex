package state

import (
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/PeterSR/spiffex/schema"
)

var compiledSchemas = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	// The embedded schemas are all there is: nothing is ever loaded from
	// elsewhere, the network least of all.
	c.UseLoader(noLoader{})
	ids := []string{schema.StateID, schema.ProviderID, schema.OriginID}
	files := []string{"state.schema.json", "provider.schema.json", "origin.schema.json"}
	for i, name := range files {
		f, err := schema.FS.Open(name)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		if err := c.AddResource(ids[i], doc); err != nil {
			return nil, err
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, id := range ids {
		s, err := c.Compile(id)
		if err != nil {
			return nil, err
		}
		out[id] = s
	}
	return out, nil
})

type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, errors.New("schema " + url + " is not embedded")
}

var printer = message.NewPrinter(language.English)

// validateSchema checks a decoded document against one of the schemas and
// returns each failure as a problem, located in the document.
func validateSchema(id string, doc any) Problems {
	schemas, err := compiledSchemas()
	if err != nil {
		return Problems{{Message: "the embedded schemas do not compile: " + err.Error()}}
	}
	err = schemas[id].Validate(doc)
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return Problems{{Message: err.Error()}}
	}
	var problems Problems
	seen := map[Problem]bool{}
	var walk func(e *jsonschema.ValidationError, parent []string)
	walk = func(e *jsonschema.ValidationError, parent []string) {
		loc := e.InstanceLocation
		if _, ok := e.ErrorKind.(*kind.PropertyNames); ok {
			loc = propertyNamesLocation(e, parent)
		} else if len(loc) < len(parent) {
			// Errors under propertyNames locate the name at the root.
			loc = parent
		}
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c, loc)
			}
			return
		}
		p := Problem{Path: instancePath(doc, loc), Message: e.ErrorKind.LocalizedString(printer)}
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}
	walk(verr, nil)
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return problems
}

// propertyNamesLocation locates a propertyNames failure. The library
// records its location without copying a buffer it goes on to reuse, so the
// location is rebuilt from the enclosing error's, which is copied, and the
// schema location, which in these schemas is always .../properties/<name>/
// propertyNames.
func propertyNamesLocation(e *jsonschema.ValidationError, parent []string) []string {
	loc := slices.Clone(parent)
	_, frag, _ := strings.Cut(e.SchemaURL, "#")
	tokens := strings.Split(strings.TrimPrefix(frag, "/"), "/")
	if n := len(tokens); n >= 3 && tokens[n-1] == "propertyNames" && tokens[n-3] == "properties" {
		loc = append(loc, tokens[n-2])
	}
	return loc
}

// instancePath turns a schema error's location into a problem path, using
// the document to tell list indexes from object members.
func instancePath(doc any, tokens []string) string {
	path := ""
	cur := doc
	for _, tok := range tokens {
		switch v := cur.(type) {
		case []any:
			i, err := strconv.Atoi(tok)
			if err == nil && i >= 0 && i < len(v) {
				path = index(path, i)
				cur = v[i]
				continue
			}
		case map[string]any:
			path = field(path, tok)
			cur = v[tok]
			continue
		}
		path = field(path, tok)
		cur = nil
	}
	return path
}

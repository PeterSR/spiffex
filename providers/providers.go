// Package providers holds the provider documents spiffex ships with (SPEC
// section 5). They are ordinary provider documents, in the format operators
// write themselves and checked by the same rules.
package providers

import (
	"embed"
	"io/fs"
	"slices"
	"strings"
)

//go:embed *.yaml
var files embed.FS

// Names returns the names of the shipped providers, sorted.
func Names() []string {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		panic(err) // embedded at build time; cannot fail
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	slices.Sort(names)
	return names
}

// Source returns the document of the shipped provider with the given name,
// byte for byte as it ships.
func Source(name string) ([]byte, bool) {
	if !slices.Contains(Names(), name) {
		return nil, false
	}
	data, err := files.ReadFile(name + ".yaml")
	if err != nil {
		return nil, false
	}
	return data, true
}

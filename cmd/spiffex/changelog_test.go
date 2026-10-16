package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/changelog-section.sh gives the release notes of a version: its
// section of the changelog, and an error when there is none.
func TestChangelogSection(t *testing.T) {
	script, err := filepath.Abs(filepath.Join(repoRoot, "scripts", "changelog-section.sh"))
	if err != nil {
		t.Fatal(err)
	}
	changelog := writeFile(t, t.TempDir(), "CHANGELOG.md", `# Changelog

## [Unreleased]

## [1.1.0] - 2026-02-01

### Added

- A fenced example:

  `+"```"+`markdown
  ## [1.0.0] is not a heading here
  [x]: https://example.org/not-a-footer
  `+"```"+`

- See [the docs][docs].

[docs]: https://example.org/docs

More text after a link definition.

## [1.1.0-rc.1] - 2026-01-15

- The candidate.

## [1.0.0] - 2026-01-01

- The first.

[Unreleased]: https://example.org/compare/v1.1.0...HEAD
[1.1.0]: https://example.org/v1.1.0
`)
	run := func(version string) (string, error) {
		out, err := exec.Command("sh", script, version, changelog).Output()
		return string(out), err
	}

	out, err := run("v1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "### Added\n") || !strings.Contains(out, "## [1.0.0] is not a heading here\n") ||
		!strings.Contains(out, "[docs]: https://example.org/docs\n") || !strings.HasSuffix(out, "More text after a link definition.\n") {
		t.Errorf("1.1.0:\n%s", out)
	}
	if out, err := run("1.1.0-rc.1"); err != nil || out != "- The candidate.\n" {
		t.Errorf("1.1.0-rc.1: %v\n%q", err, out)
	}
	if out, err := run("1.0.0"); err != nil || out != "- The first.\n" {
		t.Errorf("1.0.0, the last section, before the footer: %v\n%q", err, out)
	}
	for _, version := range []string{"Unreleased", "2.0.0", "1.1"} {
		if out, err := run(version); err == nil {
			t.Errorf("%s: want an error, got\n%s", version, out)
		}
	}
}

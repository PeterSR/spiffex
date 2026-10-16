#!/bin/sh
# Prints the CHANGELOG.md section of one version, without its heading, for the release notes.
# Fails when the section is missing or empty.
#
#   scripts/changelog-section.sh 0.1.0-rc.1 [CHANGELOG.md]
#
# A leading v is ignored, so a tag name works too. Headings and link definitions inside fenced
# code blocks are part of the text. The section ends at the next "## [" heading, or at the link
# definitions that close the file.
set -eu
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 VERSION [CHANGELOG]" >&2
  exit 2
fi
version=${1#v}
changelog=${2:-CHANGELOG.md}
notes=$(HEADING="## [$version]" awk '
  function fence(s) { return s ~ /^[ ]*(```|~~~)/ }
  function linkdef(s) { return s ~ /^ ? ? ?\[[^]]+\]:[ \t]*[^ \t]/ }
  { line[NR] = $0 }
  END {
    heading = ENVIRON["HEADING"]
    # The footer: the link definitions and blank lines after the last other line, outside fences.
    infence = 0
    lastbody = 0
    for (i = 1; i <= NR; i++) {
      if (fence(line[i])) { infence = !infence; lastbody = i; continue }
      if (infence || (line[i] !~ /^[ \t]*$/ && !linkdef(line[i]))) { lastbody = i }
    }
    infence = 0
    found = 0
    for (i = 1; i <= lastbody; i++) {
      if (fence(line[i])) { infence = !infence }
      else if (!infence && index(line[i], "## [") == 1) {
        if (found) { break }
        if (substr(line[i], 1, length(heading)) == heading) { found = 1; continue }
      }
      if (found) { print line[i] }
    }
  }
' "$changelog")
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "$changelog has no section, or an empty one, for version $version" >&2
  exit 1
fi
# Without the blank lines around it.
printf '%s\n' "$notes" | awk 'NF { started = 1 } started { buf[++n] = $0; if (NF) last = n } END { for (i = 1; i <= last; i++) print buf[i] }'

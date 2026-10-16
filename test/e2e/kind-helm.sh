#!/usr/bin/env bash
# The end-to-end test of kind.sh, with the issuer installed by the Helm chart.
set -euo pipefail
INSTALL=helm exec "$(dirname "$0")/kind.sh" "$@"

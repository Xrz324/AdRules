#!/bin/bash
set -euo pipefail

# Compatibility entry point.  Content-stage policy lives in Python so it can
# be tested and reused by the explicit rule pipeline without duplicating the
# filtering/minimization logic in shell.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/content_pipeline.py" "$@"

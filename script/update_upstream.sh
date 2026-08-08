#!/bin/bash
set -euo pipefail

# Compatibility entry point.  Upstream source selection, download retries,
# normalization, mirror reuse, and failure handling live in Python so the
# stage can be tested without sourcing shell functions or reproducing state
# across xargs workers.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/upstream_pipeline.py" "$@"

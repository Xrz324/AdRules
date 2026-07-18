#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

eval "$(sed -n '/^get_download_filename() {/,/^}/p' "${ROOT_DIR}/script/update_upstream.sh")"

assert_filename() {
    local url="$1"
    local expected_suffix="$2"
    local actual

    actual=$(get_download_filename "$url")
    if [[ ! "$actual" =~ ^[0-9a-f]{8}_${expected_suffix}$ ]]; then
        printf 'unexpected filename for %s: %s\n' "$url" "$actual" >&2
        return 1
    fi
}

assert_filename "https://example.test/SMAdHosts" 'SMAdHosts\.txt'
assert_filename "https://example.test/hosts" 'hosts\.txt'
assert_filename "https://example.test/rules.txt" 'rules\.txt'
assert_filename "https://example.test/list?format=hosts" 'list\.txt'

printf 'update_upstream filename tests passed\n'

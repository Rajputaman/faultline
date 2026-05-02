#!/usr/bin/env bash
set -euo pipefail

baseline="docs/deadcode-baseline.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

deadcode -test ./cmd/faultline | sort > "$tmp"

if ! diff -u "$baseline" "$tmp"; then
  echo
  echo "deadcode output differs from $baseline"
  echo "Review the unreachable functions. If they are intentional public API or planned hooks, update the baseline intentionally."
  exit 1
fi

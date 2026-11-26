#!/usr/bin/env bash
# Full verification: cargo fmt check, clippy with warnings denied, cargo test. Stops at the first
# failing step and names it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() {
  local name="$1"
  shift
  echo "▶ $name"
  if ! "$@"; then
    echo "✗ verify FAILED at step: $name"
    exit 1
  fi
}

step "cargo fmt --check" cargo fmt --all --check
step "cargo clippy" cargo clippy --all-targets -- -D warnings
step "cargo test" cargo test
echo "✓ verify passed"

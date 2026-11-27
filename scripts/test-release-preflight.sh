#!/usr/bin/env bash
# Tests scripts/release-preflight.sh against a throwaway local remote holding the tag v0.1.0.
#
#   scripts/test-release-preflight.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git init -q --bare "$work/remote.git"
git init -q "$work/clone"
git -C "$work/clone" -c user.name=test -c user.email=test@example.invalid \
  commit -q --allow-empty -m init
git -C "$work/clone" tag v0.1.0
git -C "$work/clone" push -q "$work/remote.git" HEAD:refs/heads/main v0.1.0

failures=0
# expect <name> <expected exit status> <args...>; the remote is $remote
remote="$work/remote.git"
expect() {
  local name="$1" want="$2"
  shift 2
  local status=0
  RELEASE_REMOTE="$remote" scripts/release-preflight.sh "$@" >"$work/out" 2>&1 || status=$?
  if [[ "$status" -eq "$want" ]]; then
    echo "  ✓ $name"
  else
    echo "  ✗ $name: exited $status, expected $want"
    sed 's/^/    /' "$work/out"
    failures=$((failures + 1))
  fi
}

echo "▶ release-preflight"
expect "a fresh tag on main is allowed" 0 0.2.0 refs/heads/main false
expect "a fresh tag on main is allowed in a dry run" 0 0.2.0 refs/heads/main true
expect "an existing tag is refused" 1 0.1.0 refs/heads/main false
expect "an existing tag is refused in a dry run" 1 0.1.0 refs/heads/main true
expect "a ref other than main is refused" 1 0.2.0 refs/heads/feat/x false
expect "a ref other than main is allowed in a dry run" 0 0.2.0 refs/heads/feat/x true
remote="$work/missing.git"
expect "a remote that cannot be read is refused" 1 0.2.0 refs/heads/main false
remote="$work/remote.git"
expect "a version that is not semver is refused" 1 v0.2.0 refs/heads/main false
expect "a dry_run that is not a boolean is a usage error" 2 0.2.0 refs/heads/main yes

if [[ "$failures" -gt 0 ]]; then
  echo "✗ test-release-preflight: $failures failure(s)"
  exit 1
fi
echo "✓ test-release-preflight passed"

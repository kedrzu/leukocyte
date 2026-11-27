#!/usr/bin/env bash
# Tests scripts/lib/keychain.sh, the CI signing keychain of scripts/bundle.sh, against a throwaway
# self-signed identity: the certificate imports and signs, and on every exit path (success, a failed
# step, a wrong .p12 password, SIGTERM) the keychain is deleted, the user's keychain search list is
# restored and no secret reaches the output or the argv of `security`.
#
#   scripts/test-keychain.sh
#
# It changes the user's keychain search list while it runs, and puts it back.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

work="$(mktemp -d)"
original_list="$(security list-keychains -d user)"
restore() {
  if [[ "$(security list-keychains -d user)" != "$original_list" ]]; then
    echo "test-keychain: restoring the search list the code under test left behind" >&2
    local paths=()
    local line
    while IFS= read -r line; do
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line#\"}"
      paths+=("${line%\"}")
    done <<<"$original_list"
    security list-keychains -d user -s "${paths[@]}"
  fi
  rm -rf "$work"
}
trap restore EXIT

# A self-signed code-signing identity. /usr/bin/openssl (LibreSSL) writes a .p12 that every
# macOS `security import` reads.
p12_password='te st"pass\word'
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=leukocyte keychain test" \
  -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=critical,codeSigning" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
/usr/bin/openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" \
  -passout fd:3 -out "$work/identity.p12" 3<<<"$p12_password"
certificate="$(base64 <"$work/identity.p12" | tr -d '\n')"
payload="$work/payload"
cp /usr/bin/true "$payload"
export payload

# A `security` first on PATH that records its argv: the commands that take a password must only
# ever arrive on stdin (`security -i`).
mkdir "$work/bin"
cat >"$work/bin/security" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >>"$SECURITY_ARGV_LOG"
exec /usr/bin/security "$@"
SH
chmod +x "$work/bin/security"
export SECURITY_ARGV_LOG="$work/argv"

failures=0
fail() {
  echo "  ✗ $*"
  failures=$((failures + 1))
}

# The bodies the cases run after the import, in the child shell that sourced the library.
case_sign() {
  [[ "$(security list-keychains -d user)" == *"\"$KEYCHAIN\""* ]] || {
    echo "the keychain is not in the search list"
    return 1
  }
  local hash
  hash="$(security find-identity -p codesigning "$KEYCHAIN" | awk '/leukocyte keychain test/ { print $2; exit }')"
  [[ -n "$hash" ]] || {
    echo "the identity is not in the keychain"
    return 1
  }
  codesign --force --sign "$hash" --keychain "$KEYCHAIN" "$payload"
  codesign --verify "$payload"
}
case_fail() { false; }
case_none() { :; }
case_sigterm() {
  kill -TERM $$
  sleep 5
}
export -f case_sign case_fail case_none case_sigterm

# The child: bundle.sh's setup and trap, then the case's body.
child="$(
  cat <<'SH'
set -euo pipefail
source scripts/lib/keychain.sh
trap keychain_cleanup EXIT
trap "exit 143" TERM
keychain_import_certificate
"$1"
SH
)"

# run_case <name> <expected exit status, or "fail" for any but 0> <.p12 password> <body function>
run_case() {
  local name="$1" expect="$2" password="$3" body="$4"
  echo "▶ $name"
  mkdir "$work/tmp"
  local status=0
  : >"$SECURITY_ARGV_LOG"
  APPLE_CERTIFICATE="$certificate" APPLE_CERTIFICATE_PASSWORD="$password" RUNNER_TEMP="$work/tmp" \
    PATH="$work/bin:$PATH" bash -c "$child" _ "$body" >"$work/out" 2>&1 || status=$?

  if [[ "$expect" == fail && "$status" -eq 0 ]] || [[ "$expect" != fail && "$status" -ne "$expect" ]]; then
    fail "exited $status, expected $expect"
    sed 's/^/    /' "$work/out"
  fi
  [[ -z "$(ls -A "$work/tmp")" ]] || fail "the keychain directory was left behind: $(ls -A "$work/tmp")"
  rm -rf "$work/tmp"
  [[ "$(security list-keychains -d user)" == "$original_list" ]] || fail "the search list was not restored"
  if grep -qF "$password" "$work/out" || grep -qF "${certificate:0:40}" "$work/out"; then
    fail "a secret appeared in the output"
  fi
  grep -q '^-i' "$SECURITY_ARGV_LOG" || fail "security -i never ran: the argv check saw nothing"
  if grep -qE '(^| )(create-keychain|unlock-keychain|import|set-key-partition-list)( |$)' "$SECURITY_ARGV_LOG" ||
    grep -qF "$password" "$SECURITY_ARGV_LOG"; then
    fail "a password reached the argv of security: $(cut -d' ' -f1 "$SECURITY_ARGV_LOG" | sort -u | tr '\n' ' ')"
  fi
}

run_case "imports, signs and cleans up" 0 "$p12_password" case_sign
run_case "cleans up after a failed step" 1 "$p12_password" case_fail
run_case "cleans up after a wrong .p12 password" fail 'wrong password' case_none
run_case "cleans up on SIGTERM" 143 "$p12_password" case_sigterm

if [[ "$failures" -gt 0 ]]; then
  echo "✗ test-keychain: $failures failure(s)"
  exit 1
fi
echo "✓ test-keychain passed"

# shellcheck shell=bash
# A temporary keychain holding the Developer ID certificate in CI, for scripts/bundle.sh (and
# scripts/test-keychain.sh, which runs it against a throwaway identity). Source it, then:
#
#   trap keychain_cleanup EXIT
#   keychain_import_certificate   # reads APPLE_CERTIFICATE (base64 .p12) and APPLE_CERTIFICATE_PASSWORD
#   codesign ... --keychain "$KEYCHAIN" ...
#
# No secret ever reaches argv: the keychain and .p12 passwords go to `security -i` on stdin through
# the printf builtin, and the decoded .p12 is a 0600 file inside a 0700 directory that
# keychain_cleanup deletes. Never run this under `set -x`.

KEYCHAIN=""
_keychain_dir=""
_keychain_password=""
_keychain_saved_search_list=()
_keychain_search_list_saved=0

# Runs one `security` command read from stdin, so its arguments stay out of the process table.
# One command per call: `security -i` exits with the status of the last command only.
_keychain_security() {
  printf '%s\n' "$1" | security -i
}

# Quotes a value for `security -i`, which takes "..." with backslash escapes.
_keychain_quote() {
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

_keychain_read_search_list() {
  local line
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line#\"}"
    line="${line%\"}"
    [[ -n "$line" ]] && printf '%s\n' "$line"
  done < <(security list-keychains -d user)
}

# Creates and unlocks the keychain, imports the certificate, lets codesign use its key without a
# prompt and puts the keychain first in the user's search list.
keychain_import_certificate() {
  : "${APPLE_CERTIFICATE:?APPLE_CERTIFICATE must hold the base64 .p12}"
  : "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD must hold the .p12 password}"
  if [[ "$APPLE_CERTIFICATE_PASSWORD" == *$'\n'* ]]; then
    echo "APPLE_CERTIFICATE_PASSWORD contains a newline, which security -i cannot take" >&2
    return 1
  fi

  local saved
  while IFS= read -r saved; do
    _keychain_saved_search_list+=("$saved")
  done < <(_keychain_read_search_list)
  _keychain_search_list_saved=1

  # Resolved, as `security list-keychains` prints it (/var is /private/var).
  _keychain_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/leukocyte-signing.XXXXXX")"
  _keychain_dir="$(cd "$_keychain_dir" && pwd -P)"
  KEYCHAIN="$_keychain_dir/signing.keychain-db"
  _keychain_password="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
  local kc pw
  kc="$(_keychain_quote "$KEYCHAIN")"
  pw="$(_keychain_quote "$_keychain_password")"

  _keychain_security "create-keychain -p $pw $kc"
  _keychain_security "set-keychain-settings -lut 21600 $kc"
  _keychain_security "unlock-keychain -p $pw $kc"

  local p12="$_keychain_dir/certificate.p12"
  (
    umask 077
    printf '%s' "$APPLE_CERTIFICATE" | base64 --decode >"$p12"
  )
  local p12_password
  p12_password="$(_keychain_quote "$APPLE_CERTIFICATE_PASSWORD")"
  local imported=0
  _keychain_security "import $(_keychain_quote "$p12") -k $kc -f pkcs12 -P $p12_password -T /usr/bin/codesign" || imported=$?
  rm -f "$p12"
  [[ "$imported" -eq 0 ]] || return "$imported"
  _keychain_security "set-key-partition-list -S apple-tool:,apple:,codesign: -s -k $pw $kc" >/dev/null

  security list-keychains -d user -s "$KEYCHAIN" ${_keychain_saved_search_list[@]+"${_keychain_saved_search_list[@]}"}
}

# Restores the search list and deletes the keychain and everything beside it. Safe to call more
# than once and before keychain_import_certificate ran; reports, rather than hides, a failed step.
keychain_cleanup() {
  local failed=0
  if [[ "$_keychain_search_list_saved" -eq 1 ]]; then
    if security list-keychains -d user -s ${_keychain_saved_search_list[@]+"${_keychain_saved_search_list[@]}"}; then
      _keychain_search_list_saved=0
    else
      echo "warning: could not restore the keychain search list" >&2
      failed=1
    fi
  fi
  if [[ -n "$KEYCHAIN" && -e "$KEYCHAIN" ]]; then
    security delete-keychain "$KEYCHAIN" || {
      echo "warning: could not delete $KEYCHAIN" >&2
      failed=1
    }
  fi
  if [[ -n "$_keychain_dir" ]]; then
    rm -rf "$_keychain_dir"
    _keychain_dir=""
  fi
  KEYCHAIN=""
  _keychain_password=""
  return "$failed"
}

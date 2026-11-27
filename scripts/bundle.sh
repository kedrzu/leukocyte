#!/usr/bin/env bash
# Builds Leukocyte.app: a universal (arm64 + x86_64) release binary in a signed bundle, zipped.
#
#   scripts/bundle.sh               build, sign, zip
#   scripts/bundle.sh --notarize    also notarize with Apple, staple and zip again
#
# Signing, by what the environment holds:
#   APPLE_CERTIFICATE (base64 .p12) + APPLE_CERTIFICATE_PASSWORD + APPLE_SIGNING_IDENTITY
#       CI: a temporary keychain (scripts/lib/keychain.sh), deleted on exit
#   APPLE_SIGNING_IDENTITY alone
#       local: an identity already in the login keychain (a name or its SHA-1)
#   neither
#       ad hoc (`--sign -`): runs, but cannot post notifications
# --notarize needs a Developer ID signature and APPLE_ID, APPLE_TEAM_ID, APPLE_PASSWORD (an
# app-specific password).
#
# Output: target/bundle/Leukocyte.app and target/bundle/Leukocyte-<version>.zip. No secret value is
# printed, and none is passed in argv except notarytool's --password. Never run under `set -x`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=scripts/lib/keychain.sh
source scripts/lib/keychain.sh

notarize=0
case "${1:-}" in
  "") ;;
  --notarize) notarize=1 ;;
  *)
    echo "usage: $0 [--notarize]" >&2
    exit 2
    ;;
esac

trap keychain_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

targets=(aarch64-apple-darwin x86_64-apple-darwin)
out="target/bundle"
app="$out/Leukocyte.app"

version="$(cargo metadata --no-deps --format-version 1 | plutil -extract packages.0.version raw -o - -)"
[[ -n "$version" ]] || {
  echo "could not read the version from cargo metadata" >&2
  exit 1
}
zip="$out/Leukocyte-$version.zip"

if [[ "$notarize" -eq 1 ]]; then
  : "${APPLE_SIGNING_IDENTITY:?--notarize needs a Developer ID signature: set APPLE_SIGNING_IDENTITY}"
  : "${APPLE_ID:?--notarize needs APPLE_ID}"
  : "${APPLE_TEAM_ID:?--notarize needs APPLE_TEAM_ID}"
  : "${APPLE_PASSWORD:?--notarize needs APPLE_PASSWORD}"
fi

echo "▶ cargo build --release (${targets[*]})"
cargo build --release --locked "${targets[@]/#/--target=}"

echo "▶ assembling $app"
rm -rf "$app" "$zip"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/leukocyte" \
  "target/${targets[0]}/release/leukocyte" "target/${targets[1]}/release/leukocyte"
sed "s/@VERSION@/$version/g" packaging/Info.plist >"$app/Contents/Info.plist"
cp packaging/leukocyte.icns "$app/Contents/Resources/leukocyte.icns"
plutil -lint "$app/Contents/Info.plist" >/dev/null

bundle_version="$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")"
build_version="$(plutil -extract CFBundleVersion raw -o - "$app/Contents/Info.plist")"
if [[ "$bundle_version" != "$version" || "$build_version" != "$version" ]]; then
  echo "the bundle's version ($bundle_version, build $build_version) is not Cargo.toml's ($version)" >&2
  exit 1
fi

if [[ -n "${APPLE_CERTIFICATE:-}" ]]; then
  : "${APPLE_SIGNING_IDENTITY:?APPLE_CERTIFICATE needs APPLE_SIGNING_IDENTITY too}"
  mode="Developer ID (temporary keychain)"
  echo "▶ signing: $mode"
  keychain_import_certificate
  codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" \
    --keychain "$KEYCHAIN" "$app"
elif [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  mode="Developer ID (login keychain)"
  echo "▶ signing: $mode"
  codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$app"
else
  mode="ad hoc"
  echo "▶ signing: $mode"
  codesign --force --sign - "$app"
fi
codesign --verify --strict --verbose=2 "$app"

# Without --norsrc, ditto adds AppleDouble ._ entries for local extended attributes (such as
# com.apple.provenance), which a plain `unzip` turns into files inside the bundle that break its
# seal. The check extracts with unzip and verifies the signature there.
zip_app() {
  rm -f "$zip"
  ditto -c -k --norsrc --keepParent "$app" "$zip"
  local check
  check="$(mktemp -d)"
  unzip -q "$zip" -d "$check"
  local verified=0
  codesign --verify --strict "$check/Leukocyte.app" || verified=$?
  rm -rf "$check"
  if [[ "$verified" -ne 0 ]]; then
    echo "the app unzipped from $zip fails codesign --verify" >&2
    exit 1
  fi
}
zip_app

if [[ "$notarize" -eq 1 ]]; then
  echo "▶ notarizing (this waits for Apple)"
  # notarytool takes the app-specific password only in argv or from a keychain profile; the owner
  # chose the Apple ID + app-specific password, so --password is the one secret in argv.
  submission="$out/notarytool-submit.plist"
  status=0
  xcrun notarytool submit "$zip" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_PASSWORD" --wait --output-format plist >"$submission" || status=$?
  id="$(plutil -extract id raw -o - "$submission" 2>/dev/null || true)"
  result="$(plutil -extract status raw -o - "$submission" 2>/dev/null || true)"
  if [[ "$status" -ne 0 || "$result" != "Accepted" ]]; then
    echo "notarization failed: status '${result:-unknown}', submission id '${id:-none}'" >&2
    if [[ -n "$id" ]]; then
      xcrun notarytool log "$id" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_PASSWORD" >&2 || echo "could not fetch the notarytool log" >&2
    fi
    exit 1
  fi
  xcrun stapler staple "$app"
  assessment="$(spctl --assess --type execute -vv "$app" 2>&1)"
  echo "$assessment"
  if [[ "$assessment" != *"source=Notarized Developer ID"* ]]; then
    echo "spctl does not see a notarized Developer ID app" >&2
    exit 1
  fi
  zip_app
  mode="$mode, notarized"
fi

echo
echo "✓ Leukocyte.app $version"
echo "  signing: $mode"
echo "  archs:   $(lipo -archs "$app/Contents/MacOS/leukocyte")"
echo "  app:     $app"
echo "  zip:     $zip"
echo "  sha256:  $(shasum -a 256 "$zip" | cut -d' ' -f1)"

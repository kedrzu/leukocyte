#!/usr/bin/env bash
# Renders the Homebrew cask from packaging/leukocyte.rb.tmpl into target/bundle/leukocyte.rb and
# checks its Ruby syntax.
#
#   scripts/cask.sh                      Cargo.toml's version, the sha256 of its bundle zip
#   scripts/cask.sh <version> <sha256>   the given ones (e.g. for a zip downloaded from a Release)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

out="target/bundle"
case $# in
  0)
    version="$(cargo metadata --no-deps --format-version 1 | plutil -extract packages.0.version raw -o - -)"
    zip="$out/Leukocyte-$version.zip"
    [[ -f "$zip" ]] || {
      echo "$zip does not exist: run scripts/bundle.sh first" >&2
      exit 1
    }
    sha256="$(shasum -a 256 "$zip" | cut -d' ' -f1)"
    ;;
  2)
    version="$1" sha256="$2"
    ;;
  *)
    echo "usage: $0 [<version> <sha256>]" >&2
    exit 2
    ;;
esac

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "'$version' is not a semver version" >&2
  exit 1
fi
if [[ ! "$sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "'$sha256' is not a sha256 (64 lowercase hex digits)" >&2
  exit 1
fi

mkdir -p "$out"
cask="$out/leukocyte.rb"
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha256/g" packaging/leukocyte.rb.tmpl >"$cask"
if grep -q '@[A-Z0-9]*@' "$cask"; then
  echo "$cask still holds a placeholder" >&2
  exit 1
fi
ruby -c "$cask" >/dev/null
echo "✓ $cask: leukocyte $version, sha256 $sha256"

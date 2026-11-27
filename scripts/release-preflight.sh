#!/usr/bin/env bash
# Refuses a release that must not run, before anything is built:
#
#   scripts/release-preflight.sh <version> <ref> <dry_run>
#
#   <version>  Cargo.toml's version, e.g. 0.2.0 (the tag is v<version>)
#   <ref>      the ref the workflow runs on, e.g. refs/heads/main ($GITHUB_REF)
#   <dry_run>  true or false
#
# Refused: a tag v<version> that already exists on the remote (dry run or not), and a ref other than
# main unless it is a dry run. The tag is looked up with `git ls-remote` on RELEASE_REMOTE (default
# origin); a remote that cannot be read refuses too, rather than passing as "no tag".
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <ref> <dry_run>" >&2
  exit 2
fi
version="$1" ref="$2" dry_run="$3"
remote="${RELEASE_REMOTE:-origin}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "✗ '$version' is not a semver version" >&2
  exit 1
fi
case "$dry_run" in
  true | false) ;;
  *)
    echo "✗ dry_run must be true or false, not '$dry_run'" >&2
    exit 2
    ;;
esac
tag="v$version"

if [[ "$ref" != "refs/heads/main" && "$dry_run" != true ]]; then
  echo "✗ releases are cut from main, not $ref (a dry run may use any ref)" >&2
  exit 1
fi

tags=""
if ! tags="$(git ls-remote --tags "$remote" "refs/tags/$tag")"; then
  echo "✗ could not list the tags of $remote" >&2
  exit 1
fi
if [[ -n "$tags" ]]; then
  echo "✗ the tag $tag already exists on $remote: bump the version in Cargo.toml" >&2
  exit 1
fi

echo "✓ preflight: $tag is free, ref $ref, dry run $dry_run"

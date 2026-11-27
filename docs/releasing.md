# Releasing

A release is the `Release` workflow (`.github/workflows/release.yml`), dispatched by hand on `main`. It
builds the universal `Leukocyte.app` with `scripts/bundle.sh --notarize`, then creates the tag
`v<version>` and a GitHub Release holding `Leukocyte-<version>.zip`, and pushes the cask rendered by
`scripts/cask.sh` from `packaging/leukocyte.rb.tmpl` to `Casks/leukocyte.rb` in `kedrzu/homebrew-tap`.
The version is `Cargo.toml`'s. Design: `decisions/release-pipeline-one-bundle-script-and-a-dispatch-workflow.md`.

## Steps

1. Bump `version` in `Cargo.toml`, run `cargo build` so `Cargo.lock` follows, and land the change in a
   PR titled `chore: release v<version>`.
2. Optionally rehearse: `gh workflow run release.yml -f dry_run=true`. It builds, signs and notarizes,
   and uploads the zip and the cask as the run's artifacts; it creates no tag, no Release and no tap
   commit. It runs on any branch (`--ref <branch>`).
3. Release: `gh workflow run release.yml` (on `main`).
4. Confirm: the run is green, `gh release view v<version>` lists `Leukocyte-<version>.zip`, and
   `kedrzu/homebrew-tap` has a `leukocyte <version>` commit. `brew upgrade --cask leukocyte` picks it up.

`scripts/release-preflight.sh` refuses the run before anything is built when the tag `v<version>`
already exists (dry run or not) or when a real release runs on a ref other than `main`.

## Secrets

Repository secrets, set from Bitwarden with `bun secrets push-github` (`secrets.md`):
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD`, `APPLE_TEAM_ID`. `HOMEBREW_TAP_TOKEN` is a fine-grained PAT with Contents read/write on
`kedrzu/homebrew-tap` only, set by hand (`gh secret set HOMEBREW_TAP_TOKEN`).

## When a run fails

- **Before the Release step** (preflight, build, notarization, cask): nothing was published. Fix and
  dispatch again.
- **After the Release, before the tap push:** the tag exists, so a new run is refused. Push the cask by
  hand: `gh release download v<version> -p '*.zip' -D target/bundle`, then
  `scripts/cask.sh <version> "$(shasum -a 256 target/bundle/Leukocyte-<version>.zip | cut -d' ' -f1)"`,
  and commit `target/bundle/leukocyte.rb` as `Casks/leukocyte.rb` to the tap with the message
  `leukocyte <version>`.
- **A broken release:** release the fix as the next version; never move or reuse a published tag.

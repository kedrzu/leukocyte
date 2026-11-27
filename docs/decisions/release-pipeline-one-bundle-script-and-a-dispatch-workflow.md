# Release pipeline: one bundle script and a dispatch workflow

## Status

Accepted, 2026-11-27.

## Context

Notifications work only from a Developer-ID-signed `Leukocyte.app` (see
`native-notifications-from-the-daemon.md`), so a release is no longer a bare binary: it is a
universal (arm64 + x86_64) bundle, signed with hardened runtime, notarized, stapled and zipped for a
Homebrew cask. The same steps must run on the owner's Mac (identity in the login keychain) and in
GitHub Actions (identity imported from secrets), and CI must prove the bundle builds on every PR
without any secret.

Signing credentials follow the owner's other apps: the Developer ID certificate as a base64 `.p12`
with its password, and notarization with an Apple ID, an app-specific password and the team ID.
`notarytool` takes that password only in argv or from a keychain profile it stored earlier.

A design panel proposed three shapes:

- **A, minimal:** one script whose behaviour is keyed entirely on environment variables, rendering
  the icon from the SVG on every build.
- **B, composable:** about 13 single-purpose scripts (build, lipo, assemble, keychain, sign,
  notarize, staple, …) behind a 4-job release workflow, and an upgrade marker in the cask.
- **C, common case:** one `scripts/bundle.sh [--notarize]`, `scripts/verify.sh` unchanged, the bundle
  as a separate CI job, and the `.icns` rendered once and committed.

## Options Considered

- **A.** Fewest files, and one entry point for local and CI use. Rendering the icon on every build
  needs a rasteriser on every machine (`rsvg-convert` is not part of macOS: absent on the owner's
  Mac, 2026-11-27), so the icon in a bundle would depend on what the building machine has.
  Keying notarization on the environment alone means a stray `APPLE_ID` turns a local build into a
  slow notarization.
- **B.** Each step testable and re-runnable alone, and jobs can be retried separately. The cost is
  ~13 scripts passing state through files and env, a workflow that has to move artifacts between 4
  jobs, and a keychain whose lifetime spans scripts, which makes "deleted on every exit path" hard
  to guarantee. Most of the steps have one caller.
- **C.** One script that owns the keychain's whole lifetime in a single `trap`; notarization is an
  explicit flag; the icon is an input, not a build step; `verify.sh` stays fast and cargo-only
  while the slower universal build runs in its own CI job. Steps cannot be re-run one by one: a
  failed notarization reruns the build (a few minutes).

## Decision

C, plus B's upgrade marker in the cask (the marker is superseded: see the last addendum).

- `scripts/bundle.sh [--notarize]` builds both targets, `lipo`s them, assembles
  `target/bundle/Leukocyte.app` from `packaging/Info.plist` (`@VERSION@` filled from
  `cargo metadata`), signs, verifies, and zips to `target/bundle/Leukocyte-<version>.zip`. The
  signing mode follows the environment: `APPLE_CERTIFICATE` → a temporary keychain;
  `APPLE_SIGNING_IDENTITY` alone → the login keychain; neither → ad hoc. `--notarize` adds
  `notarytool submit --wait`, `stapler staple`, an `spctl` check and a second zip.
- The temporary keychain lives in `scripts/lib/keychain.sh`: passwords reach `security` on stdin
  (`security -i`), never in argv; the decoded `.p12` is a 0600 file in a 0700 directory; an `EXIT`
  trap (with `INT`/`TERM` mapped to exits) restores the user's keychain search list and deletes the
  keychain. `scripts/test-keychain.sh` exercises it against a throwaway self-signed identity:
  success, a failed step, a wrong `.p12` password and `SIGTERM`, checking the cleanup, the output
  and the argv of `security`.
- The script checks after assembling that the bundle's `CFBundleShortVersionString` and
  `CFBundleVersion` equal `Cargo.toml`'s version.
- `scripts/icon.sh` renders `packaging/icon.svg` into `packaging/leukocyte.icns` with
  `rsvg-convert` when present, else Quick Look and `sips`; it runs when the SVG changes, and the
  `.icns` is committed.
- CI's `bundle` job (macOS, on PRs and `main`) runs the keychain test and an ad-hoc universal
  `bundle.sh`, checks the `Info.plist` and both architectures, and uploads the zip. The release
  itself is a manually dispatched workflow that runs `bundle.sh --notarize` with the secrets.

## Consequences

- One command builds a release locally and in CI; a local Developer ID build is
  `APPLE_SIGNING_IDENTITY=<SHA-1> scripts/bundle.sh`.
- The app-specific password appears in `notarytool`'s argv, visible to other processes of the same
  user on the runner for the length of the call. Accepted: it is the owner's chosen credential, and
  a keychain profile would need its own setup step on every runner.
- Changing the icon means running `scripts/icon.sh` and committing the `.icns`.
- A failed notarization reruns the whole build.
- PR builds are ad hoc signed, so they cannot post notifications; only a release can.

## Addendum: the release workflow, the cask and upgrades (2026-11-27)

cargo-dist is gone (`dist-workspace.toml`, `[profile.dist]` and its generated `release.yml`): it built
bare binaries and a formula, and a formula cannot ship the signed app that notifications need.
`release.yml` is now hand-written, one `macos-latest` job dispatched with a `dry_run` input:
`scripts/release-preflight.sh` (refuses an existing tag `v<version>`, and a ref other than `main`
unless dry run), `bundle.sh --notarize`, `scripts/cask.sh`, then, outside a dry run only, the tag and
GitHub Release (`gh release create`) and a commit of `Casks/leukocyte.rb` to `kedrzu/homebrew-tap`.
The publishing steps follow notarization in the same job, so no tag exists before Apple accepted the
build. Steps: `../releasing.md`.

The cask (`packaging/leukocyte.rb.tmpl`) installs `Leukocyte.app`, links its binary onto `PATH`, and
its `uninstall` stanza boots the agent out and deletes its plist (removed by the next addendum). It
does not install the agent: the user runs `leukocyte install`, which asks for notification
permission.

An upgrade must restart a running agent from the new app. Read in Homebrew 7.0.16's source
(`cask/upgrade.rb`, `cask/installer.rb`, 2026-11-27): `brew upgrade` runs the old cask's uninstall
(its `uninstall_preflight`, then the `uninstall` directives, `launchctl` and `delete` included) and
then the new cask's artifacts and `postflight`; a flight block is not told whether it runs for an
upgrade. So `uninstall_preflight` writes the epoch seconds to
`~/Library/Application Support/leukocyte/.reinstall-after-upgrade` when the agent's plist exists, and
`postflight` runs `leukocyte install --no-prompt` when that marker is under 600 s old, deleting it
either way. A plain uninstall leaves a marker that the next install deletes, reinstalling the agent
only if it comes within those 10 minutes.

Homebrew 7 deprecates flight blocks for declarative `*_steps` (`odeprecated` in `cask/dsl.rb`;
`brew style` reports `Cask/InstallSteps`), so users see a deprecation warning on install and
upgrade. The steps cannot replace them here: they run in Homebrew's sandbox with a temporary `HOME`
(`run_cask_sandbox` in `cask/artifact/abstract_artifact.rb`), where `leukocyte install` would write
the plist into the wrong home, and their guards test only whether a path exists, so the marker's
age cannot be checked. Revisit when Homebrew disables flight blocks.

## Addendum: the daemon follows its own executable; the cask has no hooks (2026-11-27)

The flight blocks above are replaced, not kept until Homebrew disables them: every install and
upgrade printed the deprecation warning, and `brew style` failed on the cask. Read in Homebrew
7.0.16's source (2026-11-27): `brew upgrade --cask` runs the old cask's `uninstall` stanza, then moves
the new app in, and no stanza can tell an upgrade from an uninstall, so an `uninstall launchctl:` or
`delete:` of the agent also stops it on every upgrade. The `*_steps` replacements cannot carry the
logic either (sandbox, temporary `HOME`, path-existence guards only).

So the cask keeps only `app`, `binary`, `depends_on`, `zap trash:` and a `caveats` text, and the
daemon owns its lifecycle (`src/daemon/lifecycle.rs`). At startup it records its executable's
canonical path and identity (device, inode, size, mtime). Every scan it stats the path again:

- **Replaced:** a new identity, the same on 2 scans in a row, makes it log `binary replaced,
  restarting` and exit 75; launchd's `KeepAlive { SuccessfulExit = false }` starts the new binary.
- **Missing:** missing on every scan for 120 s makes it remove the LaunchAgent plist, only when the
  plist's `ProgramArguments[0]` is this executable, log `app removed, uninstalling the login agent`
  and exit 0, which launchd does not restart; without the plist it does not load at the next login.
  An upgrade's gap between removing the old app and moving in the new one is seconds. Config, rules
  and logs stay (that is `zap`). A failed removal keeps the daemon running and is retried after
  another 120 s.
- **Off** when `LEUKOCYTE_HOME` is set or the executable is not inside an `.app`, so tests and
  `cargo` builds never restart or remove anything.

Probed on this machine (2026-11-27), with a copied app and a plist under a temporary `HOME`: moving a
new binary over the running one exited 75 within one scan pair; deleting the app exited 0 after
122 s with the plist gone.

Trade-off: cleanup after `brew uninstall` is eventual, up to about two minutes, during which the old
daemon keeps running from the deleted binary; `leukocyte uninstall` before it stops the agent at
once, and the caveats say so. The acceptance criterion for uninstall reads accordingly: no running
daemon and no login agent left behind, within two minutes. If the user deletes the app by hand, the
same cleanup runs.

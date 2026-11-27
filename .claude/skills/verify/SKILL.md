---
name: verify
description: How a change is proven to work in leukocyte — the scoped check after each task and the full protocol before claiming work done. The dev pipeline relies on it; use it before saying anything is finished, after each implementation task, and whenever asked to make the repo green.
---

# Verify

Fulfils the `dev` pipeline's `verify` contract. Both modes are scripts in `scripts/`; both stop at the
first failing step and print `✗ verify FAILED at step: <name>`.

## Scoped

```bash
scripts/verify-scoped.sh
```

Runs `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. It is
identical to Full for now, because the whole project builds and tests in seconds; it is split off when
a slow step (an end-to-end suite, the footprint run) appears, and that step then belongs to Full only.

Fix formatting with `cargo fmt --all`, never by hand.

## Full

```bash
scripts/verify.sh
```

The gate before claiming work is done, and what CI runs on `macos-latest`. Fix every failure: never
suppress a lint with `#[allow]`, never mark a test ignored to get green, never weaken an assertion.
Read the failing step's first error line before changing anything.

CI also runs a `bundle` job beside it: `scripts/test-keychain.sh`, `scripts/test-release-preflight.sh`,
an ad-hoc universal `scripts/bundle.sh` and `scripts/cask.sh`. Run them after touching `scripts/`,
`packaging/` or the toolchain targets; `verify.sh` does not cover them.

CI also runs a `sidecar` job on ubuntu. Run `bun install --frozen-lockfile`, `bun run check` and
`bun run test` after touching `tools/`, the root `package.json` or `bun.lock`; `verify.sh` does not
cover them. `tools/pushGithub.test.ts` guards that no secret value reaches argv or output: never
weaken it.

Tests that touch the machine (spawning process trees, sockets, launchd) set `LEUKOCYTE_HOME` to a
temp directory so they never touch an installed daemon.

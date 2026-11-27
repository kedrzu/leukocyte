# Secrets in a Bun sidecar

## Status

Accepted.

## Context

Releases need six Apple secrets (certificate, its password, signing identity, Apple ID, app-specific
password, team ID). The owner already keeps secrets for other repos in one Bitwarden Secrets Manager
project, managed with nzyme's `secrets` commands, which are TypeScript on Bun. This repo is Rust.

## Options Considered

- Share the Apple secrets with the other repos' keys: one copy to rotate, but every repo's prefix and
  environment would have to agree, and a change for one repo would reach the others.
- Write the tooling in Rust: no second toolchain, but it rebuilds login, caching and keychain handling that
  `@nzyme/secrets` and `@nzyme/bitwarden` already provide.
- A lightweight Bun sidecar in `tools/` using the published `@nzyme/*` packages with a small custom CLI.

## Decision

- Each project keeps its own copy of the Apple secrets, under the prefix `LEUKOCYTE_`, in the same Bitwarden
  project the other repos use. There is one environment, so no environment suffix.
- The tooling is a Bun sidecar in `tools/` with a custom CLI (`bun secrets`): nzyme's `secrets` commands plus
  `secrets push-github`. It is not part of the shipped app and has its own CI job (`sidecar`).
- CI reads only GitHub secrets. `push-github` copies the store's values there, passing each to `gh secret set`
  on stdin so none reaches argv, output or a file; `tools/pushGithub.test.ts` checks this against a fake `gh`.

## Consequences

- Rotating a secret means updating the copy of each project that uses it, then `push-github`.
- The repo gains `package.json`, `bun.lock` and `node_modules/` next to `Cargo.toml`; the `@nzyme/*` packages
  are pinned at one version and move together.
- Bitwarden access stays a local, owner-run step; no CI job depends on it.

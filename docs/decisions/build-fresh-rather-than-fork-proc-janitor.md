# Build fresh rather than fork proc-janitor

## Status

Accepted, 2026-11-26.

## Context

Several tools already clean up stray dev processes on macOS. This project needs per-repo, code-capable
rules, origin tracking of which agent started a process, and a safety model where unknown protects.
Forking the closest tool would save the platform code but not the part that matters.

## Options Considered

Prior art, read 2026-11-26:

- **proc-janitor** (Rust, MIT, about 8k lines, 7 stars, last commit 2026-09-01): regex targets plus an
  orphan check, a whitelist, kqueue on parent processes. It hardwires "orphan, then regex target, then
  whitelist".
- **devreap** (Go): scoring and an observe-first posture.
- **reap** (shell): tiered patterns, an ownership classifier, quarantine, pattern sanity checks, a dedupe
  of repeated processes.
- **agent-janitor** (Swift and C, 4 stars): lineage recorded before reparenting, SQLite history,
  consent-based kills, a keep policy, argv redaction at capture, private file modes.
- **DevWatchdog**: a menu-bar app.

Paths: fork proc-janitor, or build fresh and borrow ideas.

## Decision

Build fresh. A rule engine replaces proc-janitor's `scanner.rs`, `config.rs`, `cleaner.rs` and
`session.rs` (about 110 KB), which is most of the project; what would remain is thin platform glue that
`libproc` already provides.

Borrowed: observe-first (devreap; a fresh install only observes); quarantine and the `match` length
sanity check (reap); `newer_twins`, reap's dedupe, as a rule field; lineage recorded before
reparenting, argv redaction at capture, private file modes and the `keep` policy without its 30-day
persistence (agent-janitor); the dead-session signal (proc-janitor).

Not borrowed, on purpose: a menu-bar UI and click-to-kill (DevWatchdog, agent-janitor: the owner wants
autonomy); any built-in kill pattern (rules belong to repos); SQLite history and memory-pressure or
swap triggers (agent-janitor, reap: beyond "observe and kill stale"); worktree disk cleanup (reap); the
`agent-session` exec wrapper (agent-janitor: the identity environment covers it, and it is a follow-up
if attribution proves weak).

## Consequences

- No upstream to track and no inherited design to unpick; the cost is writing the platform layer.
- The project is deliberately narrower than its prior art: observe and kill stale, nothing else.

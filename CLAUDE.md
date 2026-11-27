# Architecture

leukocyte is a macOS daemon (a LaunchAgent, Rust, Apple Silicon first) that scans the user's own
processes every 5 s, tracks which agent started what, evaluates per-repo Luau rules and kills stale
agent-spawned dev processes (orphaned test runners, `nx` trees, headless browsers). It ships no
built-in kill rules: each registered repo owns `.leukocyte/rules.lua`, and the user has a personal
`~/.config/leukocyte/rules.lua`. Precision over recall: unknown protects, and a protect verdict
outranks a kill. Design: `docs/decisions/`.

One binary crate (daemon and CLI). Planned modules, added task by task under `src/`:

- `platform` the only macOS code: snapshot, lazy argv/cwd/env/sockets, signals, native
  notifications (`UNUserNotificationCenter`, only from `Leukocyte.app`), launchd.
- `facts` `ProcKey { pid, start }`, the process table, idle, origin, repo attribution.
- `rules` Luau sandbox, schema, `judge`.
- `engine` prefilter, `when`/`idle`, `judge`, merge, quarantine, fuse, actions.
- `kill` subtree termination with identity re-check.
- `daemon` the 5 s loop, reload, unix socket, JSONL action log, and following its own executable
  (restart when the app is replaced, removal of the LaunchAgent when it is gone).
- `cli` clap subcommands.

A small Bun sidecar in `tools/` (root `package.json`, TypeScript, not shipped) holds the release secrets:
`bun secrets …` reads them from Bitwarden and pushes them to GitHub Actions (`docs/secrets.md`). CI reads
only GitHub secrets, never Bitwarden. Design: `docs/decisions/secrets-in-a-bun-sidecar.md`.

# Essential commands

- `cargo build` / `cargo run -- <args>` / `cargo test` (one test: `cargo test <name>`).
- `scripts/verify.sh` runs `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test`; stops at the first failure and prints `✗ verify FAILED at step: <name>`. CI runs it on
  `macos-latest`. `scripts/verify-scoped.sh` is the same for now.
- `scripts/bundle.sh [--notarize]` builds the universal `target/bundle/Leukocyte.app` and its zip;
  signing follows the environment (temporary keychain from `APPLE_CERTIFICATE`, login-keychain
  `APPLE_SIGNING_IDENTITY`, or ad hoc). `scripts/cask.sh` renders the Homebrew cask from its zip. CI's
  `bundle` job runs both ad hoc, with `scripts/test-keychain.sh` and `scripts/test-release-preflight.sh`.
  Releasing: `docs/releasing.md`. `scripts/icon.sh` renders `packaging/icon.svg` into the committed
  `packaging/leukocyte.icns`. Design: `docs/decisions/release-pipeline-one-bundle-script-and-a-dispatch-workflow.md`.
- `bun install`, `bun run check` (`tsgo --noEmit`), `bun run test` (`bun test tools`): the sidecar's checks,
  CI's `sidecar` job. `bun secrets <command>`: `login`, `set`, `list`, `run`, `refresh`, `push-github`.
- Fix formatting with `cargo fmt --all`, never by hand.
- Wrap noisy commands in a redirect to `.context/cmd-logs/<name>.log` and read the log selectively
  (grep, a line range), never whole: a long log is re-read on every later turn.

# Verification and git

- The **`verify`** skill (`.claude/skills/verify/SKILL.md`) owns verification.
- The **`git-workflow`** skill (`.claude/skills/git-workflow/SKILL.md`) owns branches, commits, PRs,
  releases and landing.
- Both are the contracts of the `dev` plugin (`/dev:fix`, `/dev:task`, `/dev:feature`, `/dev:build`),
  installed from the `kedrzu-skills` marketplace in `.claude/settings.json`. The `git` plugin's hooks
  read `.claude/git.json` (`main` is protected).
- **ADRs** go to `docs/decisions/<title-slug>.md`, never numbered. Format: Status, Context, Options
  Considered, Decision, Consequences; facts carry dated evidence.

# Rust rules

- No `unwrap()` / `expect()` in production paths, except where an invariant is proven and commented.
- Never `#[allow]` a clippy lint to get green; fix the cause, or ask. A lint that is wrong for a case
  is configured in `clippy.toml` with a comment saying why.
- No `unsafe` outside `src/platform/`; each `unsafe` block has a `// SAFETY:` comment.
- Reaching for an ugly cast or a workaround means something deeper is wrong: investigate.

# Git

- **Conventional Commits are mandatory:** the PR title becomes the squash commit, and releases are cut
  from it. Never edit a `CHANGELOG` by hand.
- **Land every change you were asked to make:**
  1. Run the scoped checks.
  2. Commit and push through `git-workflow`. Never commit red, and never ask for permission to commit or
     push: authorization to make the change is authorization to land it.
  3. Before reporting done, confirm `git status --porcelain` is empty and `HEAD` equals `@{u}`.
     This governs finishing a change; it never licenses making one.

# Diagnosing failures — check, don't assume

Get direct evidence before naming a cause. A plausible story about why something broke is worse than none.

- **Read the real error first:** the failing assertion, the first error line of the log, the process
  that is supposedly missing. Use the tool that shows the actual state instead of inferring it.
- **When everything fails, look for one shared cause** (a broken build, a missing toolchain component).
  Diagnose it on one fast case, not by re-running the suite.
- **Fix the whole class, not the instance:** once you know the mechanism, grep for every occurrence.
- **An implausibly fast green is not green:** a 0 s run, or a usage banner with exit 0, did not run
  anything. Check the log.
- **Say "I don't know yet".** State hypotheses as hypotheses, and say plainly when evidence kills one.
- **A claim about macOS behaviour is verified on this machine** (a probe, `man`, the docs) before it
  goes into code or an ADR.

# Writing style

This applies to everything you write: plans, PR descriptions, issues, reviews, docs, chat replies.

- **Distill.** Every paragraph carries a fact, decision or instruction found nowhere else.
- **No filler** ("It is important to note…", "In conclusion…"). Delete the phrase; if the rest still
  reads, it was filler.
- **Don't restate the request.**
- **Omit an inapplicable section rather than writing "N/A".** A table needs 3+ rows and 2+ varying
  columns; anything smaller is bullets.
- **Name only what the reader has seen.** A label from your own working context is noise to someone
  who was not inside it.
- **Match the user's register.**
- **Write in the reader's language.** Everything committed or posted to GitHub (code, comments, docs,
  ADRs, skills, PRs, issues) is English. The owner chats in Polish: that is their local setting, in the
  gitignored `CLAUDE.local.md`, never committed.
- **Hub files stay thin.** `CLAUDE.md` and a `SKILL.md` carry routing and rules; detail goes in the
  reference they point at.

# Agent tool use

- **Locate, then window:** grep to find the range, then read it with offset/limit.
- **Pick subagent tiers by the work;** the default inherits your model, which is too expensive for
  fan-out:
  - Haiku for mechanical search;
  - Sonnet for multi-hop or semantic exploration;
  - your own model for the reasoning.
    Escalate on a thin result rather than defaulting up.

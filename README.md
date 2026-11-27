# leukocyte

A macOS daemon that kills stale dev processes left behind by AI coding agents: orphaned test runners,
`nx` executors, headless browsers. It runs as a LaunchAgent, scans your own processes every 5 s,
remembers which agent or terminal started each one, and applies rules written in Luau (a Lua dialect).
It ships no built-in kill rules: each repository owns its rules, and you may add personal ones.

A fresh install only observes. Nothing is killed until you run `leukocyte mode enforce` and a rule
says `enforce = true`.

## Install

```sh
brew install --cask kedrzu/tap/leukocyte   # Leukocyte.app, signed and notarized; `leukocyte` on PATH
leukocyte install                          # writes and starts the LaunchAgent
```

`leukocyte uninstall` stops the daemon and removes the LaunchAgent. After `brew upgrade` the running
daemon sees its app replaced and restarts from the new one within about 10 seconds. After
`brew uninstall --cask leukocyte` it sees the app gone, removes its LaunchAgent and exits within about
two minutes; run `leukocyte uninstall` first to stop it at once. `--zap` deletes the data, logs and
personal rules too.

For development, `cargo install --git https://github.com/kedrzu/leukocyte` builds a bare binary. It
runs the daemon the same way but cannot post notifications (see below).

## Notifications

The daemon notifies when a rules file fails to load or a rule fails to evaluate, and when the fuse
trips. Only `Leukocyte.app` can notify: macOS attributes a notification to the app bundle that posts
it.

`leukocyte install` asks macOS for permission once the daemon runs. If the answer is not "allowed",
it opens System Settings → Notifications → leukocyte, where you enable it (macOS may not show the
prompt at all). `leukocyte install --no-prompt` only installs the agent and opens nothing.

`leukocyte status` shows the state: `allowed`, `denied`, `not asked`, or `unavailable (…)` when the
binary does not run from `Leukocyte.app`. Errors reach `status` and the log whatever the state.

## Use

```sh
leukocyte add ~/src/my-repo   # apply ~/src/my-repo/.leukocyte/rules.lua; `remove` undoes it
leukocyte check               # what every rule would do to the processes running now; never kills
leukocyte check try.lua       # the same with a draft rules file inside a registered repo
leukocyte status              # mode, last scan, loaded rules files and their errors, kills in flight
leukocyte log [-f]            # the action log: kills, would-kills, reports, kill reports, errors
leukocyte keep <pid>          # never kill this process (until it exits or the daemon restarts)
leukocyte mode enforce        # start killing; `mode observe` goes back to logging only
leukocyte guide               # how to write rules for a repo (for you or an agent)
```

Rules files reload on save. A file that fails to load keeps its previous version in force, and the
error shows in `status`, the log and a notification.

## Writing rules

A repo's rules live in `<repo>/.leukocyte/rules.lua` and apply only to processes whose working
directory is inside that repo (any worktree counts); personal rules live in
`~/.config/leukocyte/rules.lua`. A rule names the processes it matches (a substring or regex of the
command line), the condition (abandoned by its agent, orphaned, idle for a while) and optionally a
Luau `judge`:

```lua
return {
  api = 1,
  rules = {
    { name = "orphaned nx executors", match = "nx/dist/bin/run-executor.js",
      when = "abandoned", idle = "20m", enforce = true },
  },
}
```

The guide, with the workflow for writing rules for a repo, patterns and the full reference, is
[`docs/writing-rules.md`](docs/writing-rules.md); `leukocyte guide` prints it, so an agent working in
any repo can read it. Examples: [`examples/repo-rules.lua`](examples/repo-rules.lua),
[`examples/personal-rules.lua`](examples/personal-rules.lua).

## Safety

- **Observe first.** A fresh install never kills; a rule never kills without `enforce = true`.
- **Protect wins.** Per process, protect outranks kill outranks report, across all rules files, and
  a protect on any member vetoes the kill of its tree.
- **Quarantine.** A kill verdict must hold for the rule's `quarantine` before it is acted on.
- **Fuse.** A scan that would issue more than 10 kills issues none, and notifies.
- **Hard guards**, checked by the engine and again on a fresh snapshot right before signalling: pid 0
  and 1, other users' processes, the daemon and its ancestors, agents and terminal session leaders
  (a tree kill stops at one), executables under `/System`, `/usr/libexec` and `/Applications`, and
  executables whose path cannot be resolved.
- **Identity re-check.** Every signal re-reads the process's start time first, so a reused pid is
  never signalled.
- **Private logs.** argv is redacted (secret-named flags and variables, URL credentials,
  token-shaped strings) before it reaches the log, `status` or `check`; the log is 0600 in a 0700
  directory.

## Footprint

Measured 2026-11-26 on an Apple Silicon Mac with about 950 processes, release build, observe mode,
`examples/personal-rules.lua` as the personal rules (so every process's command line is read on
every scan), 10 minutes sampled every 10 s with `scripts/footprint.sh --spawn 10`:

| Measure        | min     | avg     | max     |
| -------------- | ------- | ------- | ------- |
| RSS            | 12.5 MB | 13.0 MB | 13.2 MB |
| phys_footprint | 6.0 MB  | 6.4 MB  | 6.6 MB  |
| CPU, one core  | 0.40 %  | 0.41 %  | 0.50 %  |

A scan of about 950 processes takes 20 to 40 ms, almost all of it in the kernel calls that read
each process. Of the footprint, about 2.3 MB is live heap: the last scan's process table, kept for
`check` (about 1.1 MB), one Luau state per rules file (about 0.6 MB each), the per-process facts
(about 0.3 MB), the redaction regexes and the file-system watch. The rest is allocator slack and
the dirty pages of the system libraries the file-system watch loads.

The installed app, measured 2026-11-27 with `scripts/footprint.sh <pid> 10`: the signed, notarized
universal `Leukocyte.app` started by its LaunchAgent, about 990 processes, observe mode, no rules files
loaded:

| Measure        | min     | avg     | max     |
| -------------- | ------- | ------- | ------- |
| RSS            | 14.7 MB | 15.3 MB | 15.9 MB |
| phys_footprint | 4.5 MB  | 4.9 MB  | 5.4 MB  |
| CPU, one core  | 0.30 %  | 0.45 %  | 0.50 %  |

RSS counts the shared, clean pages of system libraries; `phys_footprint` is the memory the daemon
itself dirties, what Activity Monitor shows as Memory.

The budget is `phys_footprint` at most 8 MB and CPU under 1 % of one core on about 1000 processes.
RSS is not budgeted: it stays between 13 and 16 MB whatever the daemon does.

## Verifying an install

Run by hand after `leukocyte install`:

1. `leukocyte status` shows the daemon and its pid.
2. `kill -9 <that pid>`; within a few seconds `leukocyte status` shows a new pid (launchd restarted
   it).
3. Log out and back in; `leukocyte status` answers again.

## Limitations

- Agents are recognised by argv0 only: `node …/codex` is not seen as an agent, so its children are
  attributed to the terminal it runs in.
- A browser launched from `/Applications` (your own Chrome) is never killed, whatever a rule says.
- Origins live in the daemon's memory. After a daemon restart, a process first seen already orphaned
  and without identity environment has an unknown origin, so `abandoned` rules leave it alone.
- Only the signed release build of `Leukocyte.app` notifies. A `cargo install` binary or a local
  build reports notifications as unavailable or denied; errors still reach `status` and the log.
- macOS only, Apple Silicon first.

## Licence

MIT, see `LICENSE`.

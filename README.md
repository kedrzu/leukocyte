# leukocyte

A macOS daemon that kills stale dev processes left behind by AI coding agents: orphaned test runners,
`nx` executors, headless browsers. It runs as a LaunchAgent, scans your own processes every 5 s,
remembers which agent or terminal started each one, and applies rules written in Luau (a Lua dialect).
It ships no built-in kill rules: each repository owns its rules, and you may add personal ones.

A fresh install only observes. Nothing is killed until you run `leukocyte mode enforce` and a rule
says `enforce = true`.

## Install

```sh
brew install kedrzu/tap/leukocyte     # once the first release exists
cargo install --git https://github.com/kedrzu/leukocyte
leukocyte install                     # writes and starts the LaunchAgent
```

`leukocyte uninstall` stops the daemon and removes the LaunchAgent.

## Use

```sh
leukocyte add ~/src/my-repo   # apply ~/src/my-repo/.leukocyte/rules.lua; `remove` undoes it
leukocyte check               # what every rule would do to the processes running now; never kills
leukocyte check try.lua       # the same with a draft rules file inside a registered repo
leukocyte status              # mode, last scan, loaded rules files and their errors, kills in flight
leukocyte log [-f]            # the action log: kills, would-kills, reports, kill reports, errors
leukocyte keep <pid>          # never kill this process (until it exits or the daemon restarts)
leukocyte mode enforce        # start killing; `mode observe` goes back to logging only
```

Rules files reload on save. A file that fails to load keeps its previous version in force, and the
error shows in `status`, the log and a notification.

## Writing rules

A repo's rules live in `<repo>/.leukocyte/rules.lua` and apply only to processes whose working
directory is inside that repo (any worktree counts). Personal rules live in
`~/.config/leukocyte/rules.lua` and apply to all your processes. Examples:
[`examples/repo-rules.lua`](examples/repo-rules.lua), [`examples/personal-rules.lua`](examples/personal-rules.lua).

```lua
return {
  api = 1,
  env = { "NODE_ENV" },      -- optional: variables rules may read as p.env.NAME
  rules = {
    { name = "orphaned nx executors", match = "nx/dist/bin/run-executor.js",
      when = "abandoned", idle = "20m", enforce = true },
  },
}
```

A file returns `api = 1`, `rules`, and optionally `env`. Unknown keys are load errors.

| Rule key     | Default       | Meaning                                                                                                                                     |
| ------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`       | required      | Unique within the file; shown in the log.                                                                                                   |
| `match`      | one of the two | A substring of the command line (the executable, a space, argv joined by spaces), at least 4 characters.                                   |
| `re`         | one of the two | A regex over the same string; at least 4 characters and must not match the empty string.                                                 |
| `when`       | `"abandoned"` | `"abandoned"`: orphaned and its origin is known to be dead. `"orphaned"`: reparented to launchd (ppid 1). `"always"`: no condition.         |
| `idle`       | none          | The whole subtree has used under 0.5 % of a core and under 1 MiB/s of disk for at least this long.                                        |
| `quarantine` | `"5m"`        | A kill verdict must hold this long, scan after scan, before the kill is issued.                                                             |
| `grace`      | `"5s"`        | Time between the first signal and `SIGKILL`.                                                                                                |
| `signal`     | `"TERM"`      | The first signal: `"TERM"`, `"INT"`, `"HUP"` or `"QUIT"`.                                                                                   |
| `enforce`    | `false`       | Without it a kill is only logged as "would kill", whatever the mode.                                                                        |
| `judge`      | none          | `function(p)` returning `"kill"`, `"report"` or `"protect"` and an optional reason, or `nil` to keep the declarative verdict.               |

Durations are `"<n>s|m|h|d"` or combinations such as `"1h30m"`.

The declarative part is a kill when `when` holds and `idle` is met. `judge` is then called for every
process the matcher hits, whether or not that holds, and a verb it returns replaces the declarative
verdict. A judge has 10 ms and the file's Luau state 8 MiB; a judge that errors, runs over budget or
returns garbage gives no verdict, and no verdict never kills. The sandbox has no `io`, `os`,
`require` or `debug`.

`p`, the process a judge sees (durations in seconds, sizes in bytes; a fact that cannot be read is
`nil`, and so is a field not in this list, so arithmetic on a misspelt field errors):

| Field                 | Meaning                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------- |
| `pid`, `ppid`         | Process and parent id.                                                                                        |
| `exe`, `argv`, `cmd`  | Executable path, argument list, and the command line `match` runs on.                                         |
| `cwd`                 | Working directory.                                                                                            |
| `age`                 | Time since it started.                                                                                        |
| `rss`, `cpu`          | Resident memory; CPU over the last scan in percent of one core.                                               |
| `idle`                | How long its whole subtree has been idle (see `idle` above), counted from when the daemon first saw it.       |
| `orphan`              | Reparented to launchd.                                                                                        |
| `session_alive`       | Whether its session leader still runs.                                                                        |
| `origin`              | `{ kind = "agent" or "terminal", alive = true/false }`; both `nil` when the origin is unknown.                |
| `repo`                | Root of the registered repo it belongs to.                                                                    |
| `env`                 | The variables named in the file's `env` (identity variables such as `CLAUDE_PID` are never visible).          |
| `clients`             | TCP connections from clients to its listening ports.                                                          |
| `listening`           | Its listening TCP ports.                                                                                      |
| `parent`, `children`  | Neighbouring processes, as the same kind of view.                                                             |
| `newer_twins`         | Live processes with the same executable and argv, in the same repo, started after it.                         |

**Origin.** When the daemon first sees a process with its parent chain intact, it records the nearest
agent ancestor (argv0 `claude`, `codex`, `cursor-agent`, `aider`, `opencode`), or else the topmost
ancestor holding its terminal. A process first seen already orphaned gets its origin from the
agent's identity environment (`CLAUDE_PID`, `PASEO_AGENT_ID`), if it has one. Otherwise its origin is
unknown, and an unknown origin is never dead: `abandoned` does not hold.

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

RSS counts the shared, clean pages of system libraries; `phys_footprint` is the memory the daemon
itself dirties, what Activity Monitor shows as Memory.

The budget is `phys_footprint` at most 8 MB and CPU under 1 % of one core on about 1000 processes.
RSS is not budgeted: it stays around 13 MB whatever the daemon does.

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
- Notifications go through `osascript`, which macOS attributes to Script Editor: they show only once
  Script Editor is allowed in System Settings → Notifications. Errors always reach `status` and the
  log. Native notifications from a `Leukocyte.app` bundle are the next step.
- macOS only, Apple Silicon first.

## Licence

MIT, see `LICENSE`.

# Writing leukocyte rules

This guide is for whoever writes the rules for a repo, an AI agent included. `leukocyte guide` prints
it. leukocyte kills nothing on its own: every kill comes from a rule in a rules file, and a rule kills
only with `enforce = true` while the daemon is in `enforce` mode.

- A repo's rules live in `<repo>/.leukocyte/rules.lua`. They see only processes whose working
  directory is inside that repo (any worktree counts). Commit the file with the repo.
- Personal rules live in `~/.config/leukocyte/rules.lua` and see all of the user's processes.
- Files reload on save. A file that fails to load keeps its previous version in force, and the error
  shows in `leukocyte status`, the log and a notification.

## Workflow

1. **Find what lingers.** Look for the repo's processes that outlive the agent or terminal that
   started them: test runners in watch mode, task-runner executors and daemons, dev servers, bundler
   watchers, headless browsers. List the processes whose working directory is inside the repo (an
   orphan has parent pid 1):

   ```sh
   repo=$(git rev-parse --show-toplevel)
   lsof -nP -a -u "$USER" -d cwd -Fpn 2>/dev/null \
     | awk -v r="$repo" '/^p/{p=substr($0,2)} /^n/{n=substr($0,2); if (n==r || index(n, r"/")==1) print p}' \
     | paste -sd, - | xargs -I{} ps -o pid=,ppid=,etime=,command= -p {}
   ```

   Read the repo's scripts too (`package.json`, `Makefile`, `nx.json`, test configs): they tell
   which commands start long-lived processes and what their command lines look like.
2. **Write one rule per kind of process,** each with `enforce = false`. Match on the most specific
   part of the command line (a script path such as `nx/dist/bin/run-executor.js`, not `node`). Prefer
   `when = "abandoned"` with an `idle` threshold; see Patterns below.
3. **Register the repo:** `leukocyte add <repo>`. It reports a file that does not load. With
   `enforce = false` nothing can be killed, whatever the mode.
4. **Check against what runs now:** `leukocyte check` explains, per matched process, what each rule
   would do (`would kill`, `quarantined`, `protected`, `report only`, `no verdict: …`) and lists
   evaluation errors. `leukocyte check <file>` tries a draft file inside a registered repo instead of
   the registered one. `check` asks the running daemon, which `leukocyte install` starts. A rule that
   matches processes it must not touch is too broad: narrow `match`, or add a `judge` that protects.
5. **Observe** for a while of normal work: `leukocyte log -f` shows `would kill` lines with the rule
   and the process. Every log event carries `source` (the rules file) and `rule`, so one repo's
   lines can be filtered from `~/Library/Logs/leukocyte/actions.jsonl` with `jq`.
6. **Enforce** a rule only after the checklist below holds for it: set `enforce = true` and save.
   The daemon kills only when the user has also run `leukocyte mode enforce`; leave that to the user.

## Patterns

Orphaned task-runner executors, killed once their agent is gone and they have been idle:

```lua
return {
  api = 1,
  rules = {
    { name = "orphaned nx executors", match = "nx/dist/bin/run-executor.js",
      when = "abandoned", idle = "20m", enforce = false },
  },
}
```

A test runner in watch mode, matched by regex over the command line:

```lua
return {
  api = 1,
  rules = {
    { name = "abandoned vitest watchers", re = "vitest(\\.mjs)?( |$)",
      when = "abandoned", idle = "15m", enforce = false },
  },
}
```

Headless browsers, protected while a client is connected to them. They are often started by a test
server whose origin is unknown, so `orphaned` is the condition, and the judge decides:

```lua
return {
  api = 1,
  rules = {
    {
      name = "idle test browsers",
      match = "--remote-debugging-",
      when = "orphaned",
      idle = "10m",
      judge = function(p)
        -- nil means the sockets could not be read: unknown protects.
        if p.clients == nil or p.clients > 0 then
          return "protect", "a client is connected"
        end
        return nil -- keep the declarative verdict
      end,
      enforce = false,
    },
  },
}
```

A dev server the user runs by hand must survive: protect it by its command line, since a protect
outranks every kill from any rules file:

```lua
return {
  api = 1,
  rules = {
    { name = "keep the dev server", match = "vite --port 5173",
      when = "always", judge = function(p) return "protect", "dev server" end },
  },
}
```

More, with comments: `examples/repo-rules.lua` and `examples/personal-rules.lua` in the leukocyte
repository.

## Before `enforce = true`

- `leukocyte check` lists only processes the rule should kill, and the log has shown only such
  `would kill` lines over at least a day of normal work.
- `match` or `re` is specific to the tool: it cannot hit an editor, a language server, a database,
  or a process of another project.
- The condition is `abandoned`, or `orphaned` with an `idle` threshold and a judge that protects
  anything still in use. `always` is for protect rules and report-only rules.
- `idle` is longer than the longest pause in normal use (a long build step, a debugger session).
- A judge returns `nil` (not `"kill"`) when a fact it needs is `nil`.

## Reference

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

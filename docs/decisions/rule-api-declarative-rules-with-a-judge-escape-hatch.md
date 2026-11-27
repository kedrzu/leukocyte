# Rule API: declarative rules with a judge escape hatch

## Status

Accepted, 2026-11-26.

## Context

A rules file lives in the repo that owns it and is written by developers and agents, so the common
case (kill an orphaned `nx` executor after 20 idle minutes) must be a few declarative lines, while the
odd case (keep the newest two leaked MCP servers) must remain possible. Three independent panel designs
were compared before choosing.

## Options Considered

- **Minimal interface.** One returned table and one `judge(p)` function, about 20 names in total.
  Smallest to learn and to keep stable; but every rule re-implements matching, idle and reasons in Lua,
  runs for every process, and writes its own reason text.
- **Maximal flexibility.** `L.rule` builders, fact providers, shared libraries, `group_by`. Expresses
  nearly anything; but it is a framework to design, version and document, and shared libraries make a
  rule file depend on files outside its repo.
- **Common case first.** Declarative `reap`/`protect` blocks compiled in Rust, daemon-written reasons,
  subtree idle. Cheap and fast, and the daemon can explain every candidate; but no escape for what the
  declarative keys cannot say.

## Decision

The hybrid of the third and the first: a file returns `{ api = 1, env = {...}, rules = {...} }`. Each
rule has a `name`, a `match` (substring of the command line, or `re`), `when` (`abandoned` by default,
`orphaned`, `always`), optional `idle`, `quarantine` (default 5 m), `grace` (default 5 s), `signal`
(default `TERM`), `enforce` (default `false`) and an optional `judge(p)`. Rust prefilters by `match`
and evaluates `when` and `idle` into a declarative verdict; `judge` is then called for every process
the matcher hit, whatever that verdict, and returns a verb and reason (`kill`, `report`, `protect`)
that overrides it, or `nil` to keep it. Calling it only for processes that passed `when`/`idle` would
stop a `judge` from protecting or killing outside them; matched processes are few, so the cost is small. The daemon writes kill reasons
from the facts that matched, and `judge` reasons are appended. `abandoned` means orphaned with
`origin.alive == false`; a missing origin record protects. Unknown keys and an unsupported `api` are
load errors, as is a `match` shorter than 4 characters. Process fields are a lazy userdata, cached per
evaluation (a view kept past its evaluation reads nothing) (`pid ppid exe argv cmd cwd age rss cpu idle orphan session_alive origin repo env clients
listening parent children newer_twins`).

## Consequences

- The common rule is five lines and cannot read what it is not given; `judge` is only called for
  processes that already matched.
- Rules stay stateless: the daemon owns history and exposes it as facts.
- The API surface is one `api = 1` contract; changing a field's meaning needs `api = 2`.
- Anything outside the field list (fact providers, shared libraries, grouping) is deliberately absent
  until a real rule needs it.

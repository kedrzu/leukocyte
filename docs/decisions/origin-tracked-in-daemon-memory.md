# Origin tracked in daemon memory

## Status

Accepted, 2026-11-26.

## Context

PPID 1 alone is a weak signal: 470 of 654 user processes have PPID 1 (proc-janitor README), and the
2026-11-26 snapshot of this machine shows legitimate apps (Slack, Paseo.app) there too. What separates an
abandoned dev process from a healthy one is whether the agent or terminal that started it is still alive,
which is known only while the process still has its parent chain.

## Options Considered

- **Facts only.** Orphaned, idle, owner unknown. Stateless and restart-proof, but cannot tell an
  orphaned test tree of a live agent from an abandoned one, and a `nuxt dev` started from a live
  terminal looks like an orphan once reparented.
- **In-memory origin.** When a process is first seen with its chain intact, record
  `{ origin: ProcKey, kind: agent|terminal, repo }` and keep it after reparenting. Lost on a daemon
  restart, when it falls back to facts.
- **Persisted origin.** Survives restarts, but adds a store with its own staleness and PID-reuse
  problems for a case the next scan mostly repairs, and a file of agent identity at rest.

## Decision

In-memory origin, with two additions.

**Identity environment.** When the chain is already broken at first sight, origin comes from a fixed,
built-in list of agent-identity variables, read at first sight: `CLAUDE_PID` names the origin pid,
accepted only when that process started before this one (PID reuse); `PASEO_AGENT_ID` names the live
agent process carrying the same value. Values stay in the origin record and never reach rules, logs or
the socket. This is needed because `npx agent-browser` detaches and exits within milliseconds: all 11 such
daemons on this machine (2026-11-26) have PPID 1.

**The tty rule.** An agent is found first by walking the whole parent chain for an argv0 in a built-in
list (claude, codex, cursor-agent, aider, opencode). Only without one, the topmost ancestor holding the
process's controlling tty (the session leader) is the terminal origin. Nearest-tty is wrong because nx
gives each task its own pty: `fork.js` children were seen on ttys004 to 019 under a terminal on ttys003
(2026-11-26).

`origin.alive` is whether the origin key is still in the current scan, and `nil` when no record exists
(first seen already orphaned, or after a restart). `nil` protects.

## Consequences

- After a restart, existing orphans are protected until they are re-attributed, favouring precision over
  recall: a missed orphan costs memory, a wrong kill costs work.
- Origin anchors (agent processes and tty session leaders) are hard-guarded in `kill`: a subtree kill
  stops at one.
- No persisted store to migrate or leak; the cost is that attribution of old processes does not survive
  a daemon restart.

# Rules are Luau embedded in a Rust daemon

## Status

Accepted, 2026-11-26. The owner chose Lua; Luau is the dialect.

## Context

Whether a process is a pathogen or a healthy cell depends on facts (orphaned, owner alive, idle for
how long, connected to by anyone) combined by rules only the owning repo knows. Prior art (proc-janitor,
devreap, reap, DevWatchdog) uses a closed rule model of regexes and thresholds; per-repo, code-capable
detectors are this project's reason to exist. Constraints: native and small (a few MB of RSS, under 1 %
of a core, no Node/Bun runtime), no interpreter process per evaluation, a broken or slow rule must not
crash or stall the daemon, and rules have no I/O.

## Options Considered

- **Embedded Lua/Luau (`mlua`).** Small, designed for embedding. `mlua` 0.12.3 (docs.rs, 2026-11-26):
  `sandbox` and `set_interrupt` are available on the `luau` feature only, `set_memory_limit` is ungated,
  `luau` is vendored automatically. A probe release build with `luau`, `opt-level = "z"`, LTO and strip
  was 1.49 MB.
- **Embedded JavaScript (QuickJS).** Familiar to the repos' authors, but a larger runtime, and the
  sandbox, interrupt and memory-limit story is not first-class in the Rust bindings.
- **Declarative TOML plus CEL.** Safest and smallest, but cannot express "keep the newest N twins" or
  per-repo special cases without growing a new language; it is the closed model this project exists to
  avoid.
- **External Bun runtime.** Reuses the repos' tooling, but needs a runtime process per evaluation or a
  resident one, and breaks the footprint and "no Node/Bun" constraints.
- **WASM modules.** Strong isolation, but a rules author needs a compiler toolchain for a ten-line
  detector.

## Decision

Rules are Luau, evaluated in-process by `mlua` with `luau` and `vendored`: `Lua::sandbox(true)`, a
per-evaluation deadline through `set_interrupt`, and `set_memory_limit`. The sandbox exposes no `io`,
`os`, `require` or `debug`. The daemon is Rust and ships no kill rules.

## Consequences

- One 1.49 MB-class binary, no external runtime; rules reload without a restart.
- A rule that errors, runs over budget or returns garbage yields no verdict, and unknown protects.
- The `luau` feature vendors a C++ library, so building needs a C++ compiler (present on macOS and in
  CI).
- Rule authors write Luau, a Lua dialect with types as comments, not general-purpose JavaScript.

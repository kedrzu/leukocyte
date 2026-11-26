# leukocyte

A lightweight macOS daemon that kills stale dev processes left behind by AI coding agents: orphaned
test runners, `nx` executors, dev servers, headless browsers. It runs as a LaunchAgent, scans your
own processes every few seconds, tracks which agent started what, and applies per-repo rules written
in Lua. It ships no built-in kill rules: each repository owns its detectors.

## Status

Under construction. Nothing is released yet.

## Licence

MIT, see `LICENSE`.

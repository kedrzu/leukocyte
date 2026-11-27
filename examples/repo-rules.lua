-- Example rules for a repository: copy to `<repo>/.leukocyte/rules.lua` and run
-- `leukocyte add <repo>`. These rules see only processes whose working directory is inside the
-- repo. `leukocyte check` shows what each rule would do now; nothing is killed until
-- `leukocyte mode enforce` and a rule's own `enforce = true` are both set.
return {
  api = 1,
  rules = {
    {
      -- `nx run` forks an executor per task; when the agent that ran it dies, the executor
      -- (and its children, such as `bun ./dist/local.js`) is reparented to launchd and lingers.
      name = "orphaned nx executors",
      match = "nx/dist/bin/run-executor.js",
      -- Orphaned and the agent or terminal that started it is dead. A process whose origin is
      -- unknown (first seen already orphaned, or after a daemon restart) is never abandoned.
      when = "abandoned",
      -- The whole subtree has used under 0.5 % of a core and 1 MiB/s of disk for 20 minutes.
      idle = "20m",
      enforce = true,
    },
    {
      -- A `bun test` whose agent died mid-run: watch mode, or a hung test keeping it alive.
      name = "abandoned bun test runners",
      match = "bun test",
      when = "abandoned",
      idle = "10m",
      enforce = true,
    },
    {
      -- Chrome for Testing and Playwright browsers carry `--remote-debugging-port` or
      -- `--remote-debugging-pipe`. Chrome launched from /Applications is never killed whatever
      -- a rule says, so this can only reach downloaded test browsers.
      name = "idle test browsers",
      match = "--remote-debugging-",
      -- Orphaned is enough: these browsers are often started by a test server whose origin
      -- is not known.
      when = "orphaned",
      idle = "10m",
      -- Called for every matched process. A browser something is still connected to (a CDP
      -- client on its debugging port) is protected; `clients` is nil when the sockets cannot
      -- be read, and unknown protects too.
      judge = function(p)
        if p.clients == nil or p.clients > 0 then
          return "protect", "a client is connected"
        end
        -- nil keeps the declarative verdict: kill when orphaned and idle 10m.
        return nil
      end,
      -- Report-only until trusted: `leukocyte log` shows "would kill" lines. Flip to true once
      -- they are all right.
      enforce = false,
    },
  },
}

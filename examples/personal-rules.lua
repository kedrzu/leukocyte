-- Example personal rules: copy to `~/.config/leukocyte/rules.lua`. Unlike a repo's rules,
-- these see every process of yours. They reload on save; `leukocyte check` shows what each rule
-- would do now.
return {
  api = 1,
  -- Environment variables rules may read as `p.env.NAME`; every other variable stays unread.
  -- env = { "NODE_ENV" },
  rules = {
    {
      -- `npx agent-browser` starts a daemon
      -- (`~/.npm/_npx/<hash>/node_modules/agent-browser/bin/agent-browser-darwin-arm64`) that
      -- detaches at once, so it is orphaned from its first scan. Its origin comes from the
      -- agent's identity environment (`CLAUDE_PID`, `PASEO_AGENT_ID`); without one it is
      -- unknown, and an unknown origin is never abandoned.
      name = "abandoned agent-browser daemons",
      match = "agent-browser-darwin",
      -- The default; written out for clarity.
      when = "abandoned",
      idle = "1h",
      -- A process is killed only after it has stayed kill-ready this long (the default is 5m).
      quarantine = "5m",
      -- Time between the first signal and SIGKILL (default 5s); `signal` picks the first one
      -- ("TERM" by default, or "INT", "HUP", "QUIT").
      grace = "5s",
      signal = "TERM",
      enforce = true,
    },
    {
      -- Each agent session starts its own stdio MCP servers; a session that dies leaves them
      -- orphaned, and a busy day leaves a pile of identical ones. Keep the newest few.
      name = "leaked MCP server duplicates",
      re = "mcp-server|modelcontextprotocol",
      -- The declarative part: abandoned and idle for 30 minutes.
      when = "abandoned",
      idle = "30m",
      -- Called for every match, whatever `when` and `idle` say; a verb it returns replaces the
      -- declarative verdict, nil keeps it.
      judge = function(p)
        -- `newer_twins`: live processes with the same executable and argv, in the same
        -- registered repo, started after this one; nil outside a registered repo.
        local twins = p.newer_twins
        if p.orphan and twins ~= nil and twins >= 3 then
          return "kill", string.format("%d newer copies are running", twins)
        end
        -- Not "protect": a protect outranks every other rule's kill of this process.
        return nil
      end,
      -- Report-only until `leukocyte log` shows its "would kill" lines are right.
      enforce = false,
    },
  },
}

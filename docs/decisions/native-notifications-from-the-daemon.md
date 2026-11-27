# Native notifications from the daemon

## Status

Accepted, 2026-11-27.

## Context

The daemon notifies when a rules source fails to load or evaluate and when the fuse trips. It used to
run `osascript -e 'display notification …'`. macOS attributes those notifications to Script Editor,
so they showed only once the user allowed Script Editor in System Settings → Notifications, a setting
nobody connects with leukocyte.

The notification center attributes a notification to the app bundle of the posting process. The
daemon runs from `Leukocyte.app` (bundle id `dev.leukocyte.app`), started by launchd as a
LaunchAgent. Apple Developer Forums thread 804854 says `UNUserNotificationCenter` does not work from a
launch agent (`UNErrorCodeNotificationsNotAllowed`); the accepted answer recommends
`CFUserNotification` instead.

An experiment on the owner's Mac (2026-11-27) contradicts the thread for our setup:

- an ad-hoc signed bundle gets "Notifications are not allowed for this application" at once;
- a Developer-ID-signed bundle started by launchd posts fine once authorised;
- macOS did not show the first-run permission prompt, but listed the app in System Settings →
  Notifications, where enabling it worked.

`UNUserNotificationCenter.currentNotificationCenter()` called outside a bundle aborts the process
("bundleProxyForCurrentProcess is nil").

## Options Considered

- **Post directly from the daemon** through `UNUserNotificationCenter`. No extra process; completion
  handlers arrive on a private dispatch queue, so the daemon needs no run loop. Works only from the
  signed bundle, which the experiment confirmed.
- **A helper app launched through LaunchServices per notification.** The forum's suggested user
  context, but one app launch per notification, a second executable to sign, and no state the
  daemon can report.
- **`CFUserNotification` alerts.** Works from an agent per the thread, but these are modal dialogs
  with buttons, not banners: wrong for a background error that needs no answer.
- **`SMAppService` registration** of the agent. Changes how the agent is installed (from the app,
  not `launchctl`), which the CLI and Homebrew cask install flow do not need; it does not by itself
  make notifications work.

## Decision

The daemon posts directly through `UNUserNotificationCenter` (`objc2-user-notifications`), fire and
forget: a refused post is logged as a warning and never reaches the scan loop. It first checks that
its main bundle is `dev.leukocyte.app` inside a `.app`; otherwise notifications are a no-op and the
state is `unavailable (not running from Leukocyte.app)`, and the center is never touched.

The daemon caches the authorization state (`allowed`, `denied`, `not asked`, `unavailable`),
queried asynchronously every 60 s and after a refused post, and reports it in `leukocyte status`
with the System Settings hint when it is off.

`leukocyte install` asks for permission once the agent runs: it launches the bundle through
`open -n -W -g` with the hidden `request-notifications` subcommand, which requests alert and sound
authorization and prints the resulting state. If the state is not `allowed`, `install` opens the
app's page in System Settings → Notifications, since the prompt may not appear (see Context).
`install --no-prompt`, which the Homebrew cask runs on upgrade, opens nothing. No notification
outcome makes `install` fail, and every child it starts is killed after a timeout.

## Consequences

- Only the Developer-ID-signed release build notifies. A local or ad-hoc build reports
  `unavailable` (no bundle) or `denied`; a `cargo install` binary never notifies.
- Errors always reach `leukocyte status` and the log, whatever the notification state.
- Real delivery is checked by hand on a signed build; tests cover the state mapping, the no-bundle
  path and the commands `install` builds.
- `unsafe` for the completion handlers' arguments stays in `src/platform/notify.rs`.

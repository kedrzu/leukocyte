//! Native notifications through `UNUserNotificationCenter`, and the permission prompt that
//! `leukocyte install` runs.
//!
//! The system attributes a notification to the app bundle of the posting process, so this works
//! only when the binary runs from `Leukocyte.app` (bundle id [`BUNDLE_ID`]). Anywhere else every
//! call here is a no-op and the state is [`NotifyState::Unavailable`]: asking for the
//! notification center outside a bundle aborts the process, so nothing touches it before
//! [`bundle_check`] passes.
//!
//! Nothing here blocks the caller. The center's completion handlers run on a private dispatch
//! queue, so the daemon needs no run loop: they only write the cached state and log.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSBundle, NSError, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent,
    UNNotificationRequest, UNNotificationSettings, UNNotificationSound, UNUserNotificationCenter,
};

use super::NotifyState;

/// The bundle identifier of `Leukocyte.app`.
pub const BUNDLE_ID: &str = "dev.leukocyte.app";

/// The hidden subcommand that `install` launches inside the bundle to ask for permission.
pub const REQUEST_SUBCOMMAND: &str = "request-notifications";

/// Where the user turns notifications on.
pub const SETTINGS_HINT: &str = "enable in System Settings → Notifications → leukocyte";

/// How often the daemon asks the system for the authorization state.
const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// How long `request-notifications` waits for the user's answer.
pub const REQUEST_WAIT: Duration = Duration::from_secs(60);
/// How long `install` lets the `open` child run: the answer's wait plus a margin to launch.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(70);
/// How long `install` lets `open` take to show System Settings.
const SETTINGS_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `request-notifications` waits for the settings once the answer came.
const SETTINGS_WAIT: Duration = Duration::from_secs(5);

const OPEN: &str = "/usr/bin/open";
const NO_BUNDLE: &str = "not running from Leukocyte.app";

/// Posts notifications for the daemon and keeps the authorization state it reports.
pub struct Notifier {
    /// `None` when not running from the bundle: then nothing is posted.
    center: Option<Retained<UNUserNotificationCenter>>,
    state: Arc<Mutex<NotifyState>>,
    /// Set by a failed post: the state is queried again at the next [`Notifier::refresh`].
    stale: Arc<AtomicBool>,
    last_refresh: Option<Instant>,
    posted: AtomicU64,
}

impl Notifier {
    /// The notifier of this process: a working one inside `Leukocyte.app`, a no-op elsewhere.
    pub fn for_this_process() -> Self {
        match bundle_check() {
            Ok(()) => Self::with_center(UNUserNotificationCenter::currentNotificationCenter()),
            Err(reason) => Self::unavailable(reason),
        }
    }

    fn unavailable(reason: String) -> Self {
        Self {
            center: None,
            state: Arc::new(Mutex::new(NotifyState::Unavailable(reason))),
            stale: Arc::default(),
            last_refresh: None,
            posted: AtomicU64::new(0),
        }
    }

    fn with_center(center: Retained<UNUserNotificationCenter>) -> Self {
        let mut notifier = Self {
            center: Some(center),
            state: Arc::new(Mutex::new(NotifyState::Unavailable(
                "not checked yet".to_owned(),
            ))),
            stale: Arc::default(),
            last_refresh: None,
            posted: AtomicU64::new(0),
        };
        notifier.refresh();
        notifier
    }

    /// The last authorization state the system reported.
    pub fn state(&self) -> NotifyState {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Asks the system for the authorization state when the cached one is due (every
    /// [`REFRESH_EVERY`], or after a failed post). Returns at once: the answer lands in the
    /// cache from a completion handler.
    pub fn refresh(&mut self) {
        let Some(center) = &self.center else { return };
        let due = self
            .last_refresh
            .is_none_or(|at| at.elapsed() >= REFRESH_EVERY);
        if !due && !self.stale.swap(false, Ordering::Relaxed) {
            return;
        }
        self.last_refresh = Some(Instant::now());
        let state = Arc::clone(&self.state);
        query_settings(center, move |new| {
            *state.lock().unwrap_or_else(PoisonError::into_inner) = new;
        });
    }

    /// Posts a notification and returns at once. Outside the bundle it does nothing; a post the
    /// system refuses is logged as a warning and marks the state for a refresh.
    pub fn notify(&self, title: &str, body: &str) {
        let Some(center) = &self.center else { return };
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(title));
        content.setBody(&NSString::from_str(body));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        let n = self.posted.fetch_add(1, Ordering::Relaxed);
        let id = NSString::from_str(&format!("leukocyte-{}-{n}", std::process::id()));
        let request =
            UNNotificationRequest::requestWithIdentifier_content_trigger(&id, &content, None);
        let stale = Arc::clone(&self.stale);
        // The block runs on the center's private queue; it captures only an `Arc<AtomicBool>`,
        // which is `Send + Sync`.
        let done = RcBlock::new(move |error: *mut NSError| {
            // SAFETY: the center passes either null or an `NSError` that stays alive for the
            // duration of this call; the reference does not escape it.
            if let Some(error) = unsafe { error.as_ref() } {
                // Not `eprintln!`: it panics when stderr fails, and a panic here, inside a
                // callback from Objective-C, aborts the daemon.
                let _ = writeln!(
                    io::stderr(),
                    "leukocyte: warning: notification not delivered: {}",
                    error.localizedDescription()
                );
                stale.store(true, Ordering::Relaxed);
            }
        });
        center.addNotificationRequest_withCompletionHandler(&request, Some(&done));
    }
}

/// `Ok` when this process runs from `Leukocyte.app`, else why not. Only after `Ok` may the
/// notification center be touched.
pub fn bundle_check() -> Result<(), String> {
    let bundle = NSBundle::mainBundle();
    let id = bundle.bundleIdentifier().map(|id| id.to_string());
    // A bare binary can embed an Info.plist with an identifier, but it is still not a bundle
    // the notification center knows: require the `.app` too.
    let path = bundle.bundlePath().to_string();
    if id.as_deref() == Some(BUNDLE_ID) && path.ends_with(".app") {
        Ok(())
    } else {
        Err(NO_BUNDLE.to_owned())
    }
}

/// Our state for the system's authorization status.
fn state_of(status: UNAuthorizationStatus) -> NotifyState {
    match status {
        // Provisional and ephemeral authorizations deliver, quietly or for a while.
        UNAuthorizationStatus::Authorized
        | UNAuthorizationStatus::Provisional
        | UNAuthorizationStatus::Ephemeral => NotifyState::Allowed,
        UNAuthorizationStatus::Denied => NotifyState::Denied,
        UNAuthorizationStatus::NotDetermined => NotifyState::NotAsked,
        other => NotifyState::Unavailable(format!("unknown authorization status {}", other.0)),
    }
}

/// Queries the authorization state; `answer` runs on the center's queue.
fn query_settings(
    center: &UNUserNotificationCenter,
    answer: impl Fn(NotifyState) + Send + Sync + 'static,
) {
    let block = RcBlock::new(move |settings: std::ptr::NonNull<UNNotificationSettings>| {
        // SAFETY: the center passes a valid settings object that stays alive for the duration
        // of this call; the reference does not escape it.
        let settings = unsafe { settings.as_ref() };
        answer(state_of(settings.authorizationStatus()));
    });
    center.getNotificationSettingsWithCompletionHandler(&block);
}

/// What `request-notifications` does: asks for permission to alert with sound, waits up to
/// `wait` for the answer, and returns the resulting state. Outside the bundle it asks nothing.
pub fn request_authorization(wait: Duration) -> NotifyState {
    if let Err(reason) = bundle_check() {
        return NotifyState::Unavailable(reason);
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let (tx, rx) = mpsc::channel::<Result<bool, String>>();
    // The block runs on the center's queue and captures only a `Sender`, which is `Send`.
    let block = RcBlock::new(move |granted: Bool, error: *mut NSError| {
        // SAFETY: the center passes either null or an `NSError` that stays alive for the
        // duration of this call; the reference does not escape it.
        let answer = match unsafe { error.as_ref() } {
            Some(error) => Err(error.localizedDescription().to_string()),
            None => Ok(granted.as_bool()),
        };
        // The waiter may have given up; nobody reads the answer then.
        let _ = tx.send(answer);
    });
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &block,
    );
    let granted = match rx.recv_timeout(wait) {
        Ok(Ok(granted)) => granted,
        // An error means the system refused to ask (an unsigned bundle, for one); the settings
        // below say what that leaves.
        Ok(Err(e)) => {
            eprintln!("leukocyte: the permission request failed: {e}");
            false
        }
        Err(_) => {
            return NotifyState::Unavailable(format!("no answer within {}s", wait.as_secs()));
        }
    };
    // The settings are the authoritative state; the answer is the fallback.
    let (tx, rx) = mpsc::channel();
    query_settings(&center, move |state| {
        let _ = tx.send(state);
    });
    rx.recv_timeout(SETTINGS_WAIT).unwrap_or(if granted {
        NotifyState::Allowed
    } else {
        NotifyState::Denied
    })
}

/// What the permission prompt of `install` came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    /// `--no-prompt`: nothing was opened.
    Skipped,
    /// The binary is not inside an app bundle.
    NoBundle,
    /// The state after asking; `settings_opened` when System Settings was shown because the
    /// state was not `allowed`.
    Answered {
        state: NotifyState,
        settings_opened: bool,
    },
    /// The prompt could not run.
    Failed(String),
}

/// What [`prompt`] would run.
#[derive(Debug)]
enum PromptPlan {
    Skip,
    NoBundle,
    Ask(Command),
}

fn prompt_plan(no_prompt: bool, exe: &Path, out: &Path) -> PromptPlan {
    if no_prompt {
        return PromptPlan::Skip;
    }
    match app_bundle_of(exe) {
        None => PromptPlan::NoBundle,
        Some(app) => PromptPlan::Ask(request_command(&app, out)),
    }
}

/// The `.app` directory that contains `exe`, if any.
pub fn app_bundle_of(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .find(|dir| dir.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_owned)
}

/// Launches a new instance of the bundle in the background, through LaunchServices so the
/// request is attributed to the app, and waits for it to exit with its stdout in `out`.
fn request_command(app: &Path, out: &Path) -> Command {
    let mut command = Command::new(OPEN);
    command
        .args(["-n", "-W", "-g", "--stdout"])
        .arg(out)
        .arg(app)
        .args(["--args", REQUEST_SUBCOMMAND]);
    command
}

/// Opens the app's page in System Settings → Notifications.
fn settings_command() -> Command {
    let mut command = Command::new(OPEN);
    command.arg(format!(
        "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id={BUNDLE_ID}"
    ));
    command
}

/// The permission flow of `install`: unless `no_prompt`, launches the bundle's
/// `request-notifications` and, when the answer is not `allowed`, opens System Settings.
/// Never fails and never hangs: every child is killed after a timeout.
pub fn prompt(no_prompt: bool) -> PromptOutcome {
    let exe = match std::env::current_exe().and_then(|e| e.canonicalize()) {
        Ok(exe) => exe,
        Err(e) => return PromptOutcome::Failed(format!("cannot find the executable: {e}")),
    };
    let out = std::env::temp_dir().join(format!(
        "leukocyte-notifications-{}.txt",
        std::process::id()
    ));
    let command = match prompt_plan(no_prompt, &exe, &out) {
        PromptPlan::Skip => return PromptOutcome::Skipped,
        PromptPlan::NoBundle => return PromptOutcome::NoBundle,
        PromptPlan::Ask(command) => command,
    };
    let outcome = ask(command, &out);
    // Best effort: a leftover file in the per-user temp directory harms nothing.
    let _ = fs::remove_file(&out);
    outcome
}

fn ask(mut command: Command, out: &Path) -> PromptOutcome {
    // Created by us, so `open` writes into a file we own rather than through a planted link.
    if let Err(e) = OpenOptions::new().write(true).create_new(true).open(out) {
        return PromptOutcome::Failed(format!("cannot create {}: {e}", out.display()));
    }
    if let Err(e) = run_with_timeout(&mut command, PROMPT_TIMEOUT) {
        return PromptOutcome::Failed(format!("asking for permission: {e}"));
    }
    let state = match fs::read_to_string(out) {
        Ok(text) => match text.lines().last().and_then(NotifyState::parse) {
            Some(state) => state,
            None => return PromptOutcome::Failed("the app printed no state".to_owned()),
        },
        Err(e) => return PromptOutcome::Failed(format!("cannot read {}: {e}", out.display())),
    };
    let settings_opened = state != NotifyState::Allowed
        && run_with_timeout(&mut settings_command(), SETTINGS_TIMEOUT).is_ok();
    PromptOutcome::Answered {
        state,
        settings_opened,
    }
}

/// Runs `command` with no stdio and kills it after `timeout`. A non-zero exit is an error.
fn run_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let status = wait_with_timeout(&mut child, timeout)?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("open exited with {status}")))
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // Already gone is fine; the wait below reaps it either way.
            let _ = child.kill();
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer within {}s", timeout.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn authorization_statuses_map_to_states() {
        assert_eq!(
            state_of(UNAuthorizationStatus::Authorized),
            NotifyState::Allowed
        );
        assert_eq!(
            state_of(UNAuthorizationStatus::Provisional),
            NotifyState::Allowed
        );
        assert_eq!(
            state_of(UNAuthorizationStatus::Ephemeral),
            NotifyState::Allowed
        );
        assert_eq!(state_of(UNAuthorizationStatus::Denied), NotifyState::Denied);
        assert_eq!(
            state_of(UNAuthorizationStatus::NotDetermined),
            NotifyState::NotAsked
        );
        assert_eq!(
            state_of(UNAuthorizationStatus(42)),
            NotifyState::Unavailable("unknown authorization status 42".to_owned())
        );
    }

    #[test]
    fn outside_the_bundle_notify_is_an_immediate_no_op_and_unavailable() {
        // The test binary is not inside Leukocyte.app.
        assert_eq!(bundle_check(), Err(NO_BUNDLE.to_owned()));
        let mut notifier = Notifier::for_this_process();
        assert!(notifier.center.is_none());
        assert_eq!(
            notifier.state(),
            NotifyState::Unavailable("not running from Leukocyte.app".to_owned())
        );
        let started = Instant::now();
        for _ in 0..1000 {
            notifier.notify("title", "body");
            notifier.refresh();
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            request_authorization(Duration::from_secs(60)),
            NotifyState::Unavailable("not running from Leukocyte.app".to_owned())
        );
    }

    #[test]
    fn no_prompt_builds_no_command() {
        let exe = Path::new("/Applications/Leukocyte.app/Contents/MacOS/leukocyte");
        assert!(matches!(
            prompt_plan(true, exe, Path::new("/tmp/out")),
            PromptPlan::Skip
        ));
        assert!(matches!(
            prompt_plan(
                false,
                Path::new("/opt/homebrew/bin/leukocyte"),
                Path::new("/tmp/out")
            ),
            PromptPlan::NoBundle
        ));
    }

    #[test]
    fn the_prompt_opens_the_containing_bundle_in_the_background_and_waits() {
        let exe = Path::new("/Applications/Leukocyte.app/Contents/MacOS/leukocyte");
        let PromptPlan::Ask(command) = prompt_plan(false, exe, Path::new("/tmp/out.txt")) else {
            panic!("expected a prompt");
        };
        assert_eq!(command.get_program(), OPEN);
        assert_eq!(
            args(&command),
            [
                "-n",
                "-W",
                "-g",
                "--stdout",
                "/tmp/out.txt",
                "/Applications/Leukocyte.app",
                "--args",
                "request-notifications"
            ]
        );
    }

    #[test]
    fn a_hung_child_is_killed_at_the_timeout() {
        let started = Instant::now();
        let e = run_with_timeout(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}

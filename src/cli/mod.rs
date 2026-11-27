//! The `leukocyte` command line: the daemon itself (`daemon`), its installation, and the
//! commands that talk to it over the socket or edit its config.

mod follow;
mod render;

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};

use crate::daemon::config::{Config, ConfigMode, Paths};
use crate::daemon::ipc::{self, Request, Response};
use crate::daemon::run_daemon;
use crate::facts::Repos;
use crate::platform::NotifyState;
use crate::platform::launchd;
use crate::platform::notify::{self, PromptOutcome};
use crate::rules::RuleSet;

/// How long `install` waits for the new daemon to answer.
const INSTALL_WAIT: Duration = Duration::from_secs(3);
/// How often `log -f` looks at the file.
const FOLLOW_POLL: Duration = Duration::from_millis(250);

#[derive(Parser)]
#[command(
    version,
    about = "Kills stale dev processes left by AI agents, by per-repo Luau rules"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install and start the LaunchAgent that runs the daemon, then ask for permission to
    /// show notifications
    Install {
        /// Only install and start the agent; never open anything (for upgrades)
        #[arg(long)]
        no_prompt: bool,
    },
    /// Stop the daemon and remove its LaunchAgent
    Uninstall,
    /// Register a repo: the daemon then applies its .leukocyte/rules.lua
    ///
    /// A rules file that does not load is reported at once, but the repo is registered anyway
    /// (a warning, exit code 0): the daemon applies the file as soon as it loads.
    Add {
        /// The repo's root (or any worktree of it)
        repo: PathBuf,
    },
    /// Unregister a repo
    Remove { repo: PathBuf },
    /// Never kill the running process with this pid (until it exits or the daemon restarts)
    Keep { pid: i32 },
    /// Show what the daemon is doing
    Status,
    /// Explain what the rules would do to the processes running now; never kills anything
    ///
    /// With a rules file, judges the processes of the repo that holds the file by that file
    /// instead of the registered rules. Without one, explains the registered rules.
    Check {
        /// A rules file to try out, inside a registered repo
        rules: Option<PathBuf>,
    },
    /// Print the guide to writing rules: the workflow for a repo, patterns, the reference
    Guide,
    /// Print the action log
    Log {
        /// Keep running and print events as they are written
        #[arg(short, long)]
        follow: bool,
    },
    /// Set the mode: observe only logs what it would kill, enforce kills
    Mode { mode: ModeArg },
    /// Run the daemon in the foreground (what the LaunchAgent runs)
    Daemon,
    /// Ask macOS for permission to notify and print the resulting state (run by `install`
    /// inside Leukocyte.app)
    #[command(name = "request-notifications", hide = true)]
    RequestNotifications,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Observe,
    Enforce,
}

impl From<ModeArg> for ConfigMode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Observe => Self::Observe,
            ModeArg::Enforce => Self::Enforce,
        }
    }
}

/// Why a command failed.
#[derive(Debug)]
enum CliError {
    /// Nothing listens on the socket.
    NotRunning,
    Message(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => f.write_str(
                "the daemon is not running: start it with `leukocyte install` \
                 (or `leukocyte daemon` in a terminal)",
            ),
            Self::Message(message) => f.write_str(message),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        Self::Message(e.to_string())
    }
}

fn fail<T>(message: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::Message(message.into()))
}

/// Runs the command line and returns the process's exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("leukocyte: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Cmd) -> Result<ExitCode, CliError> {
    let paths = Paths::from_env()?;
    match command {
        Cmd::Install { no_prompt } => install(&paths, no_prompt),
        Cmd::Uninstall => {
            launchd::uninstall()?;
            println!("uninstalled the LaunchAgent; config and logs are left in place");
            Ok(())
        }
        Cmd::Add { repo } => add(&paths, &repo),
        Cmd::Remove { repo } => remove(&paths, &repo),
        Cmd::Keep { pid } => match ask(&Request::Keep { pid })? {
            Response::Kept { pid, .. } => {
                println!("keeping pid {pid} until it exits or the daemon restarts");
                Ok(())
            }
            other => unexpected(&other),
        },
        Cmd::Status => match ask(&Request::Status)? {
            Response::Status(status) => {
                print!("{}", render::status(&status));
                Ok(())
            }
            other => unexpected(&other),
        },
        Cmd::Check { rules } => check(rules.as_deref()),
        Cmd::Guide => {
            print!("{}", crate::rules::GUIDE);
            Ok(())
        }
        Cmd::Log { follow } => log(&paths, follow),
        Cmd::Mode { mode } => set_mode(&paths, mode.into()),
        // The only command whose exit code varies: launchd restarts a non-zero exit.
        Cmd::Daemon => return Ok(run_daemon()?.into()),
        Cmd::RequestNotifications => {
            println!("{}", notify::request_authorization(notify::REQUEST_WAIT));
            Ok(())
        }
    }?;
    Ok(ExitCode::SUCCESS)
}

/// Sends `request` to the daemon; an error response becomes the error.
fn ask(request: &Request) -> Result<Response, CliError> {
    match ipc::request(request) {
        Ok(Response::Error { message }) => fail(message),
        Ok(response) => Ok(response),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(CliError::NotRunning)
        }
        Err(e) => fail(format!("the daemon's socket: {e}")),
    }
}

fn unexpected<T>(response: &Response) -> Result<T, CliError> {
    fail(format!("unexpected answer from the daemon: {response:?}"))
}

fn install(paths: &Paths, no_prompt: bool) -> Result<(), CliError> {
    paths.create_dirs()?;
    Config::create_default(&paths.config_file())?;
    let plist = launchd::install(&paths.daemon_log())?;
    println!("installed {}", plist.display());
    let deadline = Instant::now() + INSTALL_WAIT;
    loop {
        if matches!(ipc::request(&Request::Status), Ok(Response::Status(_))) {
            println!("the daemon is running; its mode is observe until `leukocyte mode enforce`");
            println!("logs: {}", paths.logs.display());
            println!("  actions: {}", paths.action_log().display());
            println!("  daemon:  {}", paths.daemon_log().display());
            if let Some(line) = prompt_line(&notify::prompt(no_prompt)) {
                println!("{line}");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return fail(format!(
                "installed, but the daemon did not answer within {}s: see {}",
                INSTALL_WAIT.as_secs(),
                paths.daemon_log().display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What `install` says about the notification permission; `None` when it was not asked.
fn prompt_line(outcome: &PromptOutcome) -> Option<String> {
    let hint = notify::SETTINGS_HINT;
    Some(match outcome {
        PromptOutcome::Skipped => return None,
        PromptOutcome::NoBundle => {
            "notifications: need Leukocyte.app (brew install --cask); errors still reach \
             `leukocyte status` and the log"
                .to_owned()
        }
        PromptOutcome::Answered {
            state: NotifyState::Allowed,
            ..
        } => "notifications: allowed".to_owned(),
        PromptOutcome::Answered {
            state,
            settings_opened: true,
        } => format!("notifications: {state}; System Settings is open: {hint}"),
        PromptOutcome::Answered { state, .. } => format!("notifications: {state}; {hint}"),
        PromptOutcome::Failed(e) => format!("notifications: not asked ({e}); {hint}"),
    })
}

/// The config, or the default one when the file does not exist.
fn read_config(paths: &Paths) -> Result<Config, CliError> {
    let file = paths.config_file();
    match fs::read_to_string(&file) {
        Ok(text) => {
            Config::parse(&text).or_else(|e| fail(format!("{} is invalid: {e}", file.display())))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => fail(format!("cannot read {}: {e}", file.display())),
    }
}

fn write_config(paths: &Paths, config: &Config) -> Result<(), CliError> {
    paths.create_dirs()?;
    config.write(&paths.config_file()).or_else(|e| {
        fail(format!(
            "cannot write {}: {e}",
            paths.config_file().display()
        ))
    })
}

fn add(paths: &Paths, repo: &Path) -> Result<(), CliError> {
    // The daemon registers with the same call, so what is accepted here is accepted there.
    let repo = Repos::default()
        .register(repo)
        .or_else(|e| fail(format!("{}: {e}", repo.display())))?
        .root()
        .to_owned();
    let rules = repo.join(".leukocyte/rules.lua");
    if rules.exists() {
        match RuleSet::load_file(&rules) {
            Ok(set) => println!("{}: {} rules load", rules.display(), set.rules().len()),
            Err(e) => eprintln!(
                "WARNING: the rules do not load, and nothing from this repo applies until they do:\n  {e}"
            ),
        }
    } else {
        println!("note: {} does not exist yet", rules.display());
    }
    let mut config = read_config(paths)?;
    if config.repos.contains(&repo) {
        println!("{} is already registered", repo.display());
        return Ok(());
    }
    config.repos.push(repo.clone());
    write_config(paths, &config)?;
    println!("registered {}", repo.display());
    Ok(())
}

fn remove(paths: &Paths, repo: &Path) -> Result<(), CliError> {
    let mut config = read_config(paths)?;
    // The path may be gone (a deleted checkout): then only the spelling given can match.
    let canonical = fs::canonicalize(repo).ok();
    let before = config.repos.len();
    config
        .repos
        .retain(|r| r != repo && canonical.as_ref() != Some(r));
    if config.repos.len() == before {
        return fail(format!("{} is not registered", repo.display()));
    }
    write_config(paths, &config)?;
    println!("removed {}", repo.display());
    Ok(())
}

/// The root of the checkout holding `file`: its nearest ancestor with a `.git`.
fn repo_root_of(file: &Path) -> Option<PathBuf> {
    file.ancestors()
        .skip(1)
        .find(|d| d.join(".git").exists())
        .map(Path::to_owned)
}

fn check(rules: Option<&Path>) -> Result<(), CliError> {
    let request = match rules {
        None => Request::Check {
            repo_path: None,
            rules: None,
        },
        Some(file) => {
            let file =
                fs::canonicalize(file).or_else(|e| fail(format!("{}: {e}", file.display())))?;
            let text = fs::read_to_string(&file)
                .or_else(|e| fail(format!("cannot read {}: {e}", file.display())))?;
            let Some(root) = repo_root_of(&file) else {
                return fail(format!("{} is not inside a git repo", file.display()));
            };
            Request::Check {
                repo_path: Some(root.display().to_string()),
                rules: Some(text),
            }
        }
    };
    match ask(&request) {
        Ok(Response::Check(reply)) => {
            print!("{}", render::check(&reply));
            Ok(())
        }
        Ok(other) => unexpected(&other),
        Err(CliError::Message(message)) if message.contains("is not a registered repo") => {
            let hint = match &request {
                Request::Check {
                    repo_path: Some(root),
                    ..
                } => format!("\nregister it with: leukocyte add {root}"),
                _ => String::new(),
            };
            fail(format!("{message}{hint}"))
        }
        Err(e) => Err(e),
    }
}

fn log(paths: &Paths, follow: bool) -> Result<(), CliError> {
    let mut reader = follow::LogReader::new(paths.action_log());
    let mut printed = false;
    loop {
        for line in reader.poll()? {
            println!("{}", render::log_line(&line));
            printed = true;
        }
        if !follow {
            if !printed {
                println!("no actions logged yet ({})", paths.action_log().display());
            }
            return Ok(());
        }
        std::thread::sleep(FOLLOW_POLL);
    }
}

fn set_mode(paths: &Paths, mode: ConfigMode) -> Result<(), CliError> {
    match ask(&Request::Mode { mode }) {
        Ok(Response::Mode { mode }) => {
            println!("mode: {}", render::mode_name(mode));
            Ok(())
        }
        Ok(other) => unexpected(&other),
        Err(CliError::NotRunning) => {
            let mut config = read_config(paths)?;
            config.mode = mode;
            write_config(paths, &config)?;
            println!(
                "the daemon is not running: set mode = {} in {}, it applies when the daemon starts",
                render::mode_name(mode),
                paths.config_file().display()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_reports_every_notification_outcome_and_says_nothing_with_no_prompt() {
        assert_eq!(prompt_line(&PromptOutcome::Skipped), None);
        let line = |outcome| prompt_line(&outcome).unwrap();
        assert!(line(PromptOutcome::NoBundle).contains("need Leukocyte.app"));
        assert_eq!(
            line(PromptOutcome::Answered {
                state: NotifyState::Allowed,
                settings_opened: false
            }),
            "notifications: allowed"
        );
        let denied = line(PromptOutcome::Answered {
            state: NotifyState::Denied,
            settings_opened: true,
        });
        assert!(denied.starts_with("notifications: denied; System Settings is open"));
        assert!(denied.ends_with(notify::SETTINGS_HINT));
        assert!(
            line(PromptOutcome::Failed("timed out".to_owned())).contains("not asked (timed out)")
        );
    }

    #[test]
    fn install_takes_no_prompt_and_request_notifications_is_hidden() {
        let cli = Cli::try_parse_from(["leukocyte", "install", "--no-prompt"]).unwrap();
        assert!(matches!(cli.command, Cmd::Install { no_prompt: true }));
        let cli = Cli::try_parse_from(["leukocyte", "request-notifications"]).unwrap();
        assert!(matches!(cli.command, Cmd::RequestNotifications));
        let mut help = Vec::new();
        <Cli as clap::CommandFactory>::command()
            .write_long_help(&mut help)
            .unwrap();
        assert!(
            !String::from_utf8(help)
                .unwrap()
                .contains("request-notifications")
        );
    }
}

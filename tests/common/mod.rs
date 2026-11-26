//! A process-wide spawn lock for the integration tests, which run in parallel threads.
//!
//! On macOS std creates a pipe with `pipe()` and then sets `CLOEXEC`, not atomically. A child
//! forked by another test thread in that window inherits the pipe's write end, so the first
//! test's `output()` blocks until that child, often a long-lived one, exits. Holding this lock
//! across every `spawn()` makes pipe creation and fork one step, closing the window.
//!
//! The lock is never held while waiting for a child.

// Each test binary uses a subset of these.
#![allow(dead_code)]

use std::io;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

static SPAWN: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    SPAWN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `Command::spawn` under the lock.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    let _guard = lock();
    command.spawn()
}

/// `Command::output`: spawns under the lock, waits outside it.
pub fn output(command: &mut Command) -> io::Result<Output> {
    let child = spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?;
    child.wait_with_output()
}

/// `Command::status`: spawns under the lock, waits outside it.
pub fn status(command: &mut Command) -> io::Result<std::process::ExitStatus> {
    spawn(command)?.wait()
}

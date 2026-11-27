//! Unit tests share one process, so they share the spawn lock too: see `tests/common/mod.rs`
//! for why spawns are serialised.

use std::io;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

static SPAWN: Mutex<()> = Mutex::new(());

/// `Command::spawn` under the lock.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    let _guard = SPAWN.lock().unwrap_or_else(PoisonError::into_inner);
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

//! What the daemon knows about processes: identity, the process table, and (in later tasks) idle,
//! origin and repo attribution.

#![deny(unsafe_code)]

pub mod table;

pub use crate::platform::ProcKey;

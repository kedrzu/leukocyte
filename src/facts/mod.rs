//! What the daemon knows about processes: identity, the process table, and the facts kept
//! across scans (idle, origin, repo attribution).

#![deny(unsafe_code)]

mod idle;
pub mod origin;
pub mod repo;
mod store;
pub mod table;

pub use crate::platform::ProcKey;
pub use origin::OriginKind;
pub use repo::{RepoId, Repos};
pub use store::{FactStore, FactView, OriginFacts, ProcFacts};

//! Sentinel FIM: file integrity monitoring.
//!
//! The library holds all logic; the `sentinel-fim` binary is a thin CLI on top.

pub mod baseline;
pub mod config;
pub mod diff;
pub mod fsutil;
pub mod hash;
pub(crate) mod hex;
pub mod path;
pub mod report;
pub mod scan;
pub mod sign;
pub mod watch;

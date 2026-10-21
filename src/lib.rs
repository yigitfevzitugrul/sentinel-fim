//! Sentinel FIM: file integrity monitoring.
//!
//! The library holds all logic; the `sentinel-fim` binary is a thin CLI on top.

pub mod hash;
pub mod path;
pub mod scan;

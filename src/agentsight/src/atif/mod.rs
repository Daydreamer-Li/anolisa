//! ATIF (Agent Trajectory Interchange Format) module
//!
//! Provides ATIF v1.6 data structures and conversion logic for exporting
//! AgentSight GenAI data to the standardized trajectory format.
//!
//! The schema types live in the `agentsight-local` crate (as the `atif`
//! module) so they can be reused by cross-platform consumers without
//! pulling in Linux-only eBPF / SQLite dependencies. The converter in this
//! module depends on `genai` / `storage` and is therefore Linux-only.

#[cfg(target_os = "linux")]
pub mod converter;

pub use agentsight_local::atif::*;
#[cfg(target_os = "linux")]
pub use converter::{convert_session_to_atif, convert_trace_to_atif};

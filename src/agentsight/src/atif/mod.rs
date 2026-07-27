//! ATIF (Agent Trajectory Interchange Format) export module
//!
//! Converts AgentSight GenAI data into the shared ATIF schema defined by the
//! `agentsight-atif` crate (v1.7). This module owns only the conversion logic —
//! the data model is the public one, shared with the trajectory collector, so
//! both capture paths emit the same wire format.
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

//! Process bootstrap for the `AgentSecCore` V2 daemon.
//!
//! This independent service-framework slice deliberately has no registered wire
//! methods. It can bind and serve the UDS transport; the later protocol
//! integration supplies the concrete request dispatcher used by the same
//! bootstrap.

#![forbid(unsafe_code)]

mod bootstrap;
mod cli;
mod runtime;
mod signals;

pub use bootstrap::{
    BootstrapConfig, BootstrapError, default_service_config, serve, serve_without_handlers,
};
pub use cli::{Cli, CliError, ParseOutcome};
pub use runtime::{RuntimeError, run_with_shutdown_timeout};
pub use signals::{ProcessSignals, SignalError};

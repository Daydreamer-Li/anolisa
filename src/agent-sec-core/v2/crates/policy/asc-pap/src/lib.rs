//! Transport-independent Policy Administration Point use cases.
//!
//! PAP owns Policy and Scope revision CRUD plus Binding spec/status CRUD.
//! Policy authoring is lowered synchronously through [`PolicyCompiler`].
//! A Binding spec is immutable at `(binding_id, binding_revision)`; mutable
//! lifecycle is represented separately by
//! [`asc_policy_types::binding::BindingStatus`].
//! Target-specific translation, Adapter dispatch, and retries are intentionally
//! outside this crate.
//!
//! TODO(policy-reconciliation): before a reconciliation worker is introduced,
//! extend the Binding persistence transaction to atomically record a durable
//! reconcile intent and its ordering/CAS token.
//! This PAP-only phase deliberately implements neither an outbox nor a worker,
//! so accepted requests remain in `PENDING_APPLY` or `PENDING_DELETE`.

#![forbid(unsafe_code)]

mod compiler;
mod error;
mod model;
mod repository;
mod service;

pub use compiler::PolicyCompiler;
pub use error::PapError;
pub use model::{BindingRevisionState, Page, PolicyRevisionState, ScopeRevisionState};
pub use repository::PapRepository;
pub use service::PapService;

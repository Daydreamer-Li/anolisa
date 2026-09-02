use asc_foundation_types::Revision;
use asc_policy_types::binding::BindingStatus;
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::PreparedScope;
use serde::{Deserialize, Serialize};

/// Durable allocation state for one Policy identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRevisionState {
    /// Highest revision ever allocated, including deleted revisions.
    pub last_allocated_revision: Revision,
    /// Highest Policy revision whose complete content is still retained.
    pub latest: Option<PreparedPolicy>,
}

/// Durable allocation state for one Scope identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRevisionState {
    /// Highest revision ever allocated, including deleted revisions.
    pub last_allocated_revision: Revision,
    /// Highest Scope revision whose complete content is still retained.
    pub latest: Option<PreparedScope>,
}

/// Durable spec-allocation and current status for one Binding identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRevisionState {
    /// Highest immutable spec revision ever allocated.
    pub last_allocated_revision: Revision,
    /// Status of `last_allocated_revision`, which is the current retained spec.
    pub status: BindingStatus,
}

/// Bounded query result with the total before pagination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page<T> {
    /// Selected records.
    pub items: Vec<T>,
    /// Total matching records before pagination.
    pub total: u64,
}

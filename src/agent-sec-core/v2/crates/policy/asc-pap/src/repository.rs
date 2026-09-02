use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::PreparedScope;

use crate::error::PapError;
use crate::model::{BindingRevisionState, Page, PolicyRevisionState, ScopeRevisionState};

/// Persistence port owned by PAP.
///
/// TODO(policy-pagination-bounds): before a concrete repository is exposed
/// through a bounded daemon transport, pass a server-owned aggregate byte
/// budget through all three list paths. Define encoded-size accounting so an
/// implementation can reject an individually oversized first record before
/// decoding/materializing it and stop before a page exceeds the remaining
/// budget.
///
/// All list implementations must apply pagination in the repository. They
/// first order the complete matching result as documented by the individual
/// method, then skip `offset` records and return at most `limit` records.
/// Identity ordering is the lexicographic byte order of `ResourceId::as_str()`.
/// `Page::total` is the matching count before `offset` and `limit` are applied.
/// These values are per-query inputs and must not be persisted.
pub trait PapRepository: Send + Sync {
    /// Inserts one immutable Policy revision or returns the identical revision.
    ///
    /// Implementations must reject a revision that is not exactly the next
    /// never-reused revision for the Policy identity.
    ///
    /// # Errors
    /// Returns conflict, serialization, or persistence failures.
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError>;

    /// Gets Policy allocation state and the latest retained revision.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError>;

    /// Gets one exact Policy revision.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError>;

    /// Lists retained Policy revisions ordered by Policy identity ascending,
    /// then numeric revision ascending.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError>;

    /// Deletes the content of one exact Policy revision without reusing it.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence failures.
    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError>;

    /// Inserts one immutable Scope revision or returns the identical revision.
    ///
    /// # Errors
    /// Returns conflict, serialization, or persistence failures.
    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError>;

    /// Gets Scope allocation state and the latest retained revision.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn get_scope_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<ScopeRevisionState>, PapError>;

    /// Gets one exact Scope revision.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_scope(&self, id: &ResourceId, revision: Revision) -> Result<PreparedScope, PapError>;

    /// Lists retained Scope revisions ordered by Scope identity ascending,
    /// then numeric revision ascending.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError>;

    /// Deletes the content of one exact Scope revision without reusing it.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence failures.
    fn delete_scope_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError>;

    /// Inserts one immutable Binding spec revision with its initial status.
    ///
    /// The spec must use exactly the next never-reused revision for the Binding
    /// identity. `initial_status` must be `PENDING_APPLY`. Implementations
    /// persist the spec and current-status transition atomically while keeping
    /// older specs immutable and retained.
    ///
    /// TODO(policy-reconciliation): this method is the transaction boundary
    /// that must later atomically persist a durable reconcile intent and its
    /// ordering/CAS token together with the new spec/current-status pointer.
    /// No outbox is written in the PAP-only phase.
    ///
    /// # Errors
    /// Returns conflict, serialization, or persistence failures.
    fn put_binding_revision(
        &self,
        spec: &PreparedBinding,
        initial_status: BindingStatus,
    ) -> Result<BindingView, PapError>;

    /// Compare-and-swaps status for one exact immutable Binding spec.
    ///
    /// Implementations must atomically require the current spec and status to
    /// equal `binding_revision` and `expected_status`, then call
    /// `expected_status.validate_successor(next_status)` or enforce an
    /// equivalent predicate. No `PreparedBinding` is rewritten.
    ///
    /// TODO(policy-reconciliation): atomically persist a request transition,
    /// durable reconcile intent, and the ordering/CAS token required to reject
    /// stale asynchronous results before a worker is introduced.
    ///
    /// # Errors
    /// Returns conflict or persistence failures.
    fn update_binding_status(
        &self,
        id: &ResourceId,
        binding_revision: Revision,
        expected_status: BindingStatus,
        next_status: BindingStatus,
    ) -> Result<BindingStatus, PapError>;

    /// Gets the current Binding status and allocation state.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn get_binding_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<BindingRevisionState>, PapError>;

    /// Gets one exact immutable Binding spec revision.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_binding_spec(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedBinding, PapError>;

    /// Gets the current Binding spec and status as a read-only aggregate.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError>;

    /// Lists current Binding specs and status ordered by Binding identity
    /// ascending, then numeric Binding revision ascending.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError>;
}

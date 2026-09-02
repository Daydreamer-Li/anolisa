//! Complete target-independent immutable Policy Binding specifications.

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};
use crate::identifiers::{ResourceId, Revision};
use crate::policy::PreparedPolicy;
use crate::scope::PreparedScope;

/// Complete Adapter-independent immutable Binding specification.
///
/// Lifecycle and reconciliation state do not belong to this value. The pair
/// `(binding_id, binding_revision)` identifies exactly one immutable spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedBinding {
    /// Stable Binding identity.
    pub binding_id: ResourceId,
    /// Immutable spec revision.
    pub binding_revision: Revision,
    /// Exactly one authored and lowered Policy revision.
    pub policy: PreparedPolicy,
    /// Exactly one authored Scope revision.
    pub scope: PreparedScope,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedBindingWire {
    binding_id: ResourceId,
    binding_revision: Revision,
    policy: PreparedPolicy,
    scope: PreparedScope,
    #[serde(default, rename = "executionDomainId")]
    _legacy_execution_domain_id: Option<ResourceId>,
}

impl<'de> Deserialize<'de> for PreparedBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PreparedBindingWire::deserialize(deserializer)?;
        Ok(Self {
            binding_id: wire.binding_id,
            binding_revision: wire.binding_revision,
            policy: wire.policy,
            scope: wire.scope,
        })
    }
}

impl Validate for PreparedBinding {
    fn validate(&self) -> Result<(), ValidationError> {
        self.policy.validate().map_err(|error| {
            ValidationError::new(format!("policy.{}", error.path), error.message)
        })?;
        self.scope.validate().map_err(|error| {
            ValidationError::new(format!("scope.{}", error.path), error.message)
        })?;
        Ok(())
    }
}

/// Complete lifecycle state of one Binding.
///
/// Successful paths:
///
/// ```text
/// CREATE/UPDATE: PendingApply -> Applying -> Ready
/// DELETE: PendingDelete -> Deleting -> Deleted
/// ```
///
/// Request transitions:
///
/// - An identical-spec UPDATE is a no-op from `PendingApply`, `Applying`, or
///   `Ready`. From `ApplyFailed` or any Delete-side state it transitions to
///   `PendingApply`.
/// - A DELETE is a no-op from `PendingDelete`, `Deleting`, or `Deleted`. From
///   any Apply-side state or `DeleteFailed` it transitions to `PendingDelete`.
/// - A changed-spec UPDATE is handled by PAP: it allocates the next immutable
///   Binding revision and assigns that new spec `PendingApply`.
///
/// Reconciler transitions:
///
/// - `PendingApply -> Applying`; then success reaches `Ready`, a retryable
///   failure returns to `PendingApply`, and a permanent or retry-exhausted
///   failure reaches `ApplyFailed`.
/// - `PendingDelete -> Deleting`; then success reaches `Deleted`, a retryable
///   failure returns to `PendingDelete`, and a permanent or retry-exhausted
///   failure reaches `DeleteFailed`.
///
/// `Ready`, `ApplyFailed`, `Deleted`, and `DeleteFailed` are terminal without a
/// new request. [`BindingStatus::validate_successor`] is the executable closed
/// transition set used by Repository compare-and-swap implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingStatus {
    /// PAP accepted an Apply request; no worker has claimed it yet.
    PendingApply,
    /// A reconciler is applying the referenced immutable spec.
    Applying,
    /// Apply completed successfully.
    Ready,
    /// Apply exhausted retries or failed permanently.
    ApplyFailed,
    /// PAP accepted a Delete request; no worker has claimed it yet.
    PendingDelete,
    /// A reconciler is detaching the referenced immutable spec.
    Deleting,
    /// Detach completed successfully.
    Deleted,
    /// Detach exhausted retries or failed permanently.
    DeleteFailed,
}

impl BindingStatus {
    /// Reports whether no automatic transition remains without a new request.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::ApplyFailed | Self::Deleted | Self::DeleteFailed
        )
    }

    /// Returns the status produced by an identical-spec UPDATE.
    ///
    /// An identical UPDATE is a no-op while Apply is pending, running, or already
    /// successful. It returns to pending Apply after deletion or terminal Apply
    /// failure. Changed spec content is handled separately by PAP revision
    /// allocation and also starts in `PendingApply`.
    #[must_use]
    pub const fn request_apply(self) -> Self {
        if matches!(self, Self::PendingApply | Self::Applying | Self::Ready) {
            self
        } else {
            Self::PendingApply
        }
    }

    /// Returns the status produced by a DELETE request.
    ///
    /// DELETE is idempotent while deletion is pending, running, or completed;
    /// retrying a terminal Delete failure returns to pending Delete.
    #[must_use]
    pub const fn request_delete(self) -> Self {
        if matches!(self, Self::PendingDelete | Self::Deleting | Self::Deleted) {
            self
        } else {
            Self::PendingDelete
        }
    }

    /// Claims pending Apply or Delete work.
    ///
    /// # Errors
    /// Rejects non-pending source states.
    pub fn start_reconcile(self) -> Result<Self, ValidationError> {
        match self {
            Self::PendingApply => Ok(Self::Applying),
            Self::PendingDelete => Ok(Self::Deleting),
            _ => Err(illegal_status("start reconcile", self)),
        }
    }

    /// Records successful reconciliation.
    ///
    /// # Errors
    /// Rejects non-running source states.
    pub fn complete_reconcile(self) -> Result<Self, ValidationError> {
        match self {
            Self::Applying => Ok(Self::Ready),
            Self::Deleting => Ok(Self::Deleted),
            _ => Err(illegal_status("complete reconcile", self)),
        }
    }

    /// Returns failed running work to its pending state for retry.
    ///
    /// # Errors
    /// Rejects non-running source states.
    pub fn retry_reconcile(self) -> Result<Self, ValidationError> {
        match self {
            Self::Applying => Ok(Self::PendingApply),
            Self::Deleting => Ok(Self::PendingDelete),
            _ => Err(illegal_status("retry reconcile", self)),
        }
    }

    /// Records terminal reconciliation failure.
    ///
    /// # Errors
    /// Rejects non-running source states.
    pub fn fail_reconcile(self) -> Result<Self, ValidationError> {
        match self {
            Self::Applying => Ok(Self::ApplyFailed),
            Self::Deleting => Ok(Self::DeleteFailed),
            _ => Err(illegal_status("fail reconcile", self)),
        }
    }

    /// Validates a Repository compare-and-swap successor.
    ///
    /// Identical values are accepted for idempotency. Other successors must be
    /// one of the request or worker transitions exposed by this type.
    ///
    /// # Errors
    /// Rejects an illegal status transition.
    pub fn validate_successor(self, next: Self) -> Result<(), ValidationError> {
        if self == next {
            return Ok(());
        }
        let valid = matches!(
            (self, next),
            (Self::PendingApply, Self::Applying | Self::PendingDelete)
                | (
                    Self::Applying,
                    Self::Ready | Self::PendingApply | Self::ApplyFailed | Self::PendingDelete,
                )
                | (Self::Ready, Self::PendingDelete)
                | (
                    Self::ApplyFailed | Self::DeleteFailed,
                    Self::PendingApply | Self::PendingDelete,
                )
                | (Self::PendingDelete, Self::Deleting | Self::PendingApply)
                | (
                    Self::Deleting,
                    Self::Deleted | Self::PendingDelete | Self::DeleteFailed | Self::PendingApply,
                )
                | (Self::Deleted, Self::PendingApply)
        );
        if valid {
            Ok(())
        } else {
            Err(illegal_status("persist status", self))
        }
    }
}

fn illegal_status(operation: &str, status: BindingStatus) -> ValidationError {
    ValidationError::new("status", format!("cannot {operation} from {status:?}"))
}

/// Read-only aggregate of an immutable spec and its current lifecycle status.
///
/// Repositories may construct this view for GET/LIST responses. It must not be
/// updated as one opaque persistence document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingView {
    /// Immutable Binding spec.
    pub spec: PreparedBinding,
    /// Mutable lifecycle status for `spec`.
    pub status: BindingStatus,
}

impl Validate for BindingView {
    fn validate(&self) -> Result<(), ValidationError> {
        self.spec
            .validate()
            .map_err(|error| ValidationError::new(format!("spec.{}", error.path), error.message))
    }
}

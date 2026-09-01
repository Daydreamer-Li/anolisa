//! Complete target-independent Policy Binding snapshots.

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};
use crate::identifiers::{ResourceId, Revision};
use crate::policy::PreparedPolicy;
use crate::scope::PreparedScope;

/// Desired Binding state understood before any target-specific Adapter exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingDesiredState {
    /// The Adapter should converge this prepared Binding.
    Ready,
    /// The Adapter should remove this Binding.
    Absent,
}

/// Complete Adapter-independent Binding snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedBinding {
    /// Stable Binding identity.
    pub binding_id: ResourceId,
    /// Immutable desired revision.
    pub binding_revision: Revision,
    /// Exactly one authored and lowered Policy revision.
    pub policy: PreparedPolicy,
    /// Exactly one authored Scope revision.
    pub scope: PreparedScope,
    /// Desired state.
    pub desired_state: BindingDesiredState,
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
    desired_state: BindingDesiredState,
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
            desired_state: wire.desired_state,
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

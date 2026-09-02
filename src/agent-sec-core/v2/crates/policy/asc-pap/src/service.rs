use std::sync::Arc;

use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::Validate;
use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::{PreparedScope, ScopeSelector, ScopeTemplate};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::compiler::PolicyCompiler;
use crate::error::PapError;
use crate::model::Page;
use crate::repository::PapRepository;

const MAX_WRITE_ATTEMPTS: usize = 8;
const MAX_PAGE_SIZE: u32 = 1_000;

#[derive(Clone, Copy)]
enum WriteTarget<'a> {
    Create,
    Update(&'a ResourceId),
}

/// Policy Administration Point for transport-independent desired-state CRUD.
pub struct PapService<R, C> {
    repository: Arc<R>,
    compiler: Arc<C>,
}

impl<R, C> Clone for PapService<R, C> {
    fn clone(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            compiler: Arc::clone(&self.compiler),
        }
    }
}

impl<R, C> PapService<R, C>
where
    R: PapRepository,
    C: PolicyCompiler,
{
    /// Creates PAP from explicit persistence and synchronous compiler ports.
    pub fn new(repository: Arc<R>, compiler: Arc<C>) -> Self {
        Self {
            repository,
            compiler,
        }
    }

    /// Creates one Policy identity from an authored template.
    ///
    /// PAP generates the identity and starts at revision 1.
    ///
    /// # Errors
    /// Returns validation, lowering, conflict, revision, or persistence errors.
    pub fn create_policy(
        &self,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        self.write_policy(WriteTarget::Create, policy_name, template)
    }

    /// Updates one existing Policy identity to an authored template.
    ///
    /// Identical latest content is idempotent. Changed content receives the
    /// next never-reused revision and is lowered synchronously before storage.
    ///
    /// # Errors
    /// Returns validation, lowering, conflict, revision, or persistence errors.
    pub fn update_policy(
        &self,
        policy_id: &ResourceId,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        self.write_policy(WriteTarget::Update(policy_id), policy_name, template)
    }

    fn write_policy(
        &self,
        target: WriteTarget<'_>,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        validate_policy_name(policy_name)?;
        let (update_existing, mut selected_id) = match target {
            WriteTarget::Create => (false, generated_resource_id()?),
            WriteTarget::Update(id) => (true, id.clone()),
        };

        for _ in 0..MAX_WRITE_ATTEMPTS {
            let state = self.repository.get_policy_revision_state(&selected_id)?;
            if update_existing && state.is_none() {
                return Err(PapError::NotFound);
            }
            if !update_existing && state.is_some() {
                selected_id = generated_resource_id()?;
                continue;
            }
            if let Some(current) = state.as_ref().and_then(|value| value.latest.as_ref())
                && current.policy_name == policy_name
                && &current.template == template
            {
                return Ok(current.clone());
            }

            let revision =
                next_revision(state.as_ref().map(|value| value.last_allocated_revision))?;
            let candidate = self.prepare_policy(&selected_id, policy_name, revision, template)?;
            match self.repository.put_policy(&candidate) {
                Err(PapError::Conflict) => {
                    if !update_existing {
                        selected_id = generated_resource_id()?;
                    }
                }
                result => return result,
            }
        }
        Err(PapError::Conflict)
    }

    /// Gets one exact Policy revision.
    ///
    /// # Errors
    /// Returns not-found or persistence errors.
    pub fn get_policy(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.repository.get_policy(id, revision)
    }

    /// Lists retained Policy revisions.
    ///
    /// # Errors
    /// Returns invalid-pagination or persistence errors.
    pub fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        validate_limit(limit)?;
        self.repository.list_policies(limit, offset)
    }

    /// Deletes one exact Policy revision without allowing revision reuse.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence errors.
    pub fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.repository.delete_policy_revision(id, revision)
    }

    /// Creates one Scope identity from an authored selector.
    ///
    /// PAP generates the identity and starts at revision 1.
    ///
    /// # Errors
    /// Returns validation, conflict, revision, or persistence errors.
    pub fn create_scope(&self, selector: &ScopeSelector) -> Result<PreparedScope, PapError> {
        self.write_scope(WriteTarget::Create, selector)
    }

    /// Updates one existing Scope identity to an authored selector.
    ///
    /// # Errors
    /// Returns validation, conflict, revision, or persistence errors.
    pub fn update_scope(
        &self,
        scope_id: &ResourceId,
        selector: &ScopeSelector,
    ) -> Result<PreparedScope, PapError> {
        self.write_scope(WriteTarget::Update(scope_id), selector)
    }

    fn write_scope(
        &self,
        target: WriteTarget<'_>,
        selector: &ScopeSelector,
    ) -> Result<PreparedScope, PapError> {
        validate_authored_selector(selector)?;
        let template = ScopeTemplate::execution_domain_default();
        template.validate().map_err(PapError::InvalidScope)?;
        let template_digest = json_digest(&(selector, &template))?;
        let (update_existing, mut selected_id) = match target {
            WriteTarget::Create => (false, generated_resource_id()?),
            WriteTarget::Update(id) => (true, id.clone()),
        };

        for _ in 0..MAX_WRITE_ATTEMPTS {
            let state = self.repository.get_scope_revision_state(&selected_id)?;
            if update_existing && state.is_none() {
                return Err(PapError::NotFound);
            }
            if !update_existing && state.is_some() {
                selected_id = generated_resource_id()?;
                continue;
            }
            if let Some(current) = state.as_ref().and_then(|value| value.latest.as_ref())
                && &current.selector == selector
                && current.template == template
            {
                return Ok(current.clone());
            }

            let revision =
                next_revision(state.as_ref().map(|value| value.last_allocated_revision))?;
            let candidate = PreparedScope {
                scope_id: selected_id.clone(),
                revision,
                selector: selector.clone(),
                template: template.clone(),
                template_digest: template_digest.clone(),
            };
            candidate.validate().map_err(PapError::InvalidScope)?;
            match self.repository.put_scope(&candidate) {
                Err(PapError::Conflict) => {
                    if !update_existing {
                        selected_id = generated_resource_id()?;
                    }
                }
                result => return result,
            }
        }
        Err(PapError::Conflict)
    }

    /// Gets one exact Scope revision.
    ///
    /// # Errors
    /// Returns not-found or persistence errors.
    pub fn get_scope(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError> {
        self.repository.get_scope(id, revision)
    }

    /// Lists retained Scope revisions.
    ///
    /// # Errors
    /// Returns invalid-pagination or persistence errors.
    pub fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        validate_limit(limit)?;
        self.repository.list_scopes(limit, offset)
    }

    /// Deletes one exact Scope revision without allowing revision reuse.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence errors.
    pub fn delete_scope_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError> {
        self.repository.delete_scope_revision(id, revision)
    }

    /// Creates one immutable Binding spec from Policy and Scope references.
    ///
    /// PAP generates the identity, starts at revision 1, and assigns
    /// `PENDING_APPLY`.
    ///
    /// # Errors
    /// Returns not-found, validation, conflict, revision, or persistence errors.
    pub fn create_binding(
        &self,
        policy_id: &ResourceId,
        policy_revision: Revision,
        scope_id: &ResourceId,
        scope_revision: Revision,
    ) -> Result<BindingView, PapError> {
        self.write_binding(
            WriteTarget::Create,
            policy_id,
            policy_revision,
            scope_id,
            scope_revision,
        )
    }

    /// Updates one existing immutable Binding spec to Apply intent.
    ///
    /// Policy and Scope references are resolved to complete immutable snapshots.
    /// An identical spec is idempotent while Apply is pending, running, or
    /// complete. UPDATE after deletion or terminal failure returns status to
    /// pending Apply without changing identical spec content. Changed spec
    /// content receives the next never-reused revision.
    /// This PAP-only phase leaves accepted work in `PENDING_APPLY` and does not
    /// translate or dispatch the Binding.
    ///
    /// # Errors
    /// Returns not-found, validation, conflict, revision, or persistence errors.
    pub fn update_binding(
        &self,
        binding_id: &ResourceId,
        policy_id: &ResourceId,
        policy_revision: Revision,
        scope_id: &ResourceId,
        scope_revision: Revision,
    ) -> Result<BindingView, PapError> {
        self.write_binding(
            WriteTarget::Update(binding_id),
            policy_id,
            policy_revision,
            scope_id,
            scope_revision,
        )
    }

    fn write_binding(
        &self,
        target: WriteTarget<'_>,
        policy_id: &ResourceId,
        policy_revision: Revision,
        scope_id: &ResourceId,
        scope_revision: Revision,
    ) -> Result<BindingView, PapError> {
        let policy = self.repository.get_policy(policy_id, policy_revision)?;
        let scope = self.repository.get_scope(scope_id, scope_revision)?;
        let (update_existing, mut selected_id) = match target {
            WriteTarget::Create => (false, generated_resource_id()?),
            WriteTarget::Update(id) => (true, id.clone()),
        };

        for _ in 0..MAX_WRITE_ATTEMPTS {
            let state = self.repository.get_binding_revision_state(&selected_id)?;
            if update_existing && state.is_none() {
                return Err(PapError::NotFound);
            }
            if !update_existing && state.is_some() {
                selected_id = generated_resource_id()?;
                continue;
            }
            if let Some(current) = state.as_ref() {
                let current_spec = self
                    .repository
                    .get_binding_spec(&selected_id, current.last_allocated_revision)?;
                if current_spec.policy == policy && current_spec.scope == scope {
                    let next_status = current.status.request_apply();
                    if next_status == current.status {
                        return binding_view(current_spec, current.status);
                    }

                    // TODO(policy-reconciliation): atomically persist a durable Apply intent and
                    // introduce the ordering/CAS token defined by the outbox/reconciler design.
                    match self.repository.update_binding_status(
                        &selected_id,
                        current_spec.binding_revision,
                        current.status,
                        next_status,
                    ) {
                        Ok(status) => return binding_view(current_spec, status),
                        Err(PapError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
            }

            let revision =
                next_revision(state.as_ref().map(|value| value.last_allocated_revision))?;
            let spec = PreparedBinding {
                binding_id: selected_id.clone(),
                binding_revision: revision,
                policy: policy.clone(),
                scope: scope.clone(),
            };
            let initial_status = BindingStatus::PendingApply;
            binding_view(spec.clone(), initial_status)?;

            // TODO(policy-reconciliation): atomically persist a durable reconcile intent with this
            // new spec/status pointer and introduce its ordering/CAS token before any Adapter
            // worker is introduced. No outbox or dispatch is intentionally performed here.
            match self.repository.put_binding_revision(&spec, initial_status) {
                Err(PapError::Conflict) => {
                    if !update_existing {
                        selected_id = generated_resource_id()?;
                    }
                }
                result => return result,
            }
        }
        Err(PapError::Conflict)
    }

    /// Gets the current immutable Binding spec and mutable status.
    ///
    /// # Errors
    /// Returns not-found or persistence errors.
    pub fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        self.repository.get_binding(id)
    }

    /// Lists current Binding specs and status.
    ///
    /// # Errors
    /// Returns invalid-pagination or persistence errors.
    pub fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        validate_limit(limit)?;
        self.repository.list_bindings(limit, offset)
    }

    /// Accepts Delete intent without changing the Binding spec revision.
    ///
    /// The status enters `PENDING_DELETE`; repeated deletion is idempotent
    /// while pending, running, or complete. A terminal Delete failure returns to
    /// pending Delete when explicitly retried. The complete immutable spec
    /// remains available for target-side detach.
    ///
    /// # Errors
    /// Returns not-found, conflict, validation, or persistence errors.
    pub fn delete_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let Some(state) = self.repository.get_binding_revision_state(id)? else {
                return Err(PapError::NotFound);
            };
            let spec = self
                .repository
                .get_binding_spec(id, state.last_allocated_revision)?;
            let next_status = state.status.request_delete();
            if next_status == state.status {
                return binding_view(spec, state.status);
            }
            binding_view(spec.clone(), next_status)?;

            // TODO(policy-reconciliation): persist a durable Detach intent in the same
            // transaction as this status transition and its future ordering/CAS token. The
            // immutable Binding spec revision does not change.
            match self.repository.update_binding_status(
                id,
                spec.binding_revision,
                state.status,
                next_status,
            ) {
                Ok(status) => return binding_view(spec, status),
                Err(PapError::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        Err(PapError::Conflict)
    }

    fn prepare_policy(
        &self,
        policy_id: &ResourceId,
        policy_name: &str,
        revision: Revision,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        let domain_id = PolicyId::new(policy_id.as_str()).map_err(PapError::InvalidIdentifier)?;
        let input = TemplateEnvelope {
            policy_id: domain_id.clone(),
            revision,
            template: template.clone(),
        };
        let canonical_policy = self
            .compiler
            .lower(&input)
            .map_err(PapError::InvalidPolicy)?;
        if canonical_policy.policy_id != domain_id {
            return Err(PapError::InvalidPolicy(ValidationError::new(
                "canonicalPolicy.policyId",
                "compiler output must match the authored Policy identity",
            )));
        }
        if canonical_policy.revision != revision {
            return Err(PapError::InvalidPolicy(ValidationError::new(
                "canonicalPolicy.revision",
                "compiler output must match the authored Policy revision",
            )));
        }
        canonical_policy
            .validate()
            .map_err(PapError::InvalidPolicy)?;
        let candidate = PreparedPolicy {
            policy_id: policy_id.clone(),
            policy_name: policy_name.to_owned(),
            revision,
            template: template.clone(),
            canonical_policy,
            template_digest: json_digest(template)?,
        };
        candidate.validate().map_err(PapError::InvalidPolicy)?;
        Ok(candidate)
    }
}

fn binding_view(spec: PreparedBinding, status: BindingStatus) -> Result<BindingView, PapError> {
    let view = BindingView { spec, status };
    view.validate().map_err(PapError::InvalidBinding)?;
    Ok(view)
}

fn validate_policy_name(value: &str) -> Result<(), PapError> {
    if value.trim().is_empty() {
        return Err(PapError::InvalidPolicyName(
            "must contain a visible character".to_owned(),
        ));
    }
    if value.len() > 256 {
        return Err(PapError::InvalidPolicyName(
            "must not exceed 256 bytes".to_owned(),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(PapError::InvalidPolicyName(
            "must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_authored_selector(selector: &ScopeSelector) -> Result<(), PapError> {
    if matches!(selector, ScopeSelector::LegacyExecutionDomain { .. }) {
        return Err(PapError::InvalidScope(ValidationError::new(
            "selector.kind",
            "legacy execution-domain selectors cannot be authored",
        )));
    }
    selector.validate().map_err(PapError::InvalidScope)
}

fn validate_limit(limit: u32) -> Result<(), PapError> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(PapError::InvalidPagination)
    }
}

fn next_revision(current: Option<Revision>) -> Result<Revision, PapError> {
    match current {
        Some(revision) => revision
            .checked_next()
            .map_err(|_| PapError::RevisionExhausted),
        None => Revision::new(1).map_err(|_| PapError::RevisionExhausted),
    }
}

fn generated_resource_id() -> Result<ResourceId, PapError> {
    ResourceId::new(Uuid::new_v4().to_string())
        .map_err(|error| PapError::InvalidIdentifier(error.to_string()))
}

fn json_digest<T: Serialize>(value: &T) -> Result<String, PapError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PapError::Serialization)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

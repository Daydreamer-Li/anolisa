use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{
    BindingRevisionState, Page, PapError, PapRepository, PapService, PolicyCompiler,
    PolicyRevisionState, ScopeRevisionState,
};
use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::policy::{PolicyEnvelope, PreparedPolicy};
use asc_policy_types::scope::{PreparedScope, ScopeSelector};

const COMPLETE_BINDING: &str =
    include_str!("../../asc-policy-types/tests/fixtures/prepared-binding.json");

#[derive(Default)]
struct FakeState {
    policy_heads: BTreeMap<String, u32>,
    policies: BTreeMap<(String, u32), PreparedPolicy>,
    scope_heads: BTreeMap<String, u32>,
    scopes: BTreeMap<(String, u32), PreparedScope>,
    binding_heads: BTreeMap<String, u32>,
    binding_specs: BTreeMap<(String, u32), PreparedBinding>,
    binding_statuses: BTreeMap<String, BindingStatus>,
}

#[derive(Default)]
struct FakeRepository {
    state: Mutex<FakeState>,
}

impl FakeRepository {
    fn lock(&self) -> Result<MutexGuard<'_, FakeState>, PapError> {
        self.state.lock().map_err(|_| PapError::Persistence)
    }
}

impl PapRepository for FakeRepository {
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError> {
        let mut state = self.lock()?;
        let id = policy.policy_id.as_str().to_owned();
        let revision = policy.revision.get();
        let key = (id.clone(), revision);
        if let Some(existing) = state.policies.get(&key) {
            return if existing == policy {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if next_raw_revision(state.policy_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.policies.insert(key, policy.clone());
        state.policy_heads.insert(id, revision);
        Ok(policy.clone())
    }

    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.policy_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let latest = state
            .policies
            .iter()
            .filter(|((candidate, _), _)| candidate == id.as_str())
            .max_by_key(|((_, revision), _)| *revision)
            .map(|(_, policy)| policy.clone());
        Ok(Some(PolicyRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            latest,
        }))
    }

    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        let items = self.lock()?.policies.values().cloned().collect();
        Ok(page(items, limit, offset))
    }

    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .remove(&(id.as_str().to_owned(), revision.get()))
            .ok_or(PapError::NotFound)
    }

    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError> {
        let mut state = self.lock()?;
        let id = scope.scope_id.as_str().to_owned();
        let revision = scope.revision.get();
        let key = (id.clone(), revision);
        if let Some(existing) = state.scopes.get(&key) {
            return if existing == scope {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if next_raw_revision(state.scope_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.scopes.insert(key, scope.clone());
        state.scope_heads.insert(id, revision);
        Ok(scope.clone())
    }

    fn get_scope_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<ScopeRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.scope_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let latest = state
            .scopes
            .iter()
            .filter(|((candidate, _), _)| candidate == id.as_str())
            .max_by_key(|((_, revision), _)| *revision)
            .map(|(_, scope)| scope.clone());
        Ok(Some(ScopeRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            latest,
        }))
    }

    fn get_scope(&self, id: &ResourceId, revision: Revision) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        let items = self.lock()?.scopes.values().cloned().collect();
        Ok(page(items, limit, offset))
    }

    fn delete_scope_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .remove(&(id.as_str().to_owned(), revision.get()))
            .ok_or(PapError::NotFound)
    }

    fn put_binding_revision(
        &self,
        spec: &PreparedBinding,
        initial_status: BindingStatus,
    ) -> Result<BindingView, PapError> {
        let mut state = self.lock()?;
        if initial_status != BindingStatus::PendingApply {
            return Err(PapError::Conflict);
        }

        let id = spec.binding_id.as_str().to_owned();
        let revision = spec.binding_revision.get();
        let key = (id.clone(), revision);

        if let Some(existing) = state.binding_specs.get(&key) {
            if existing != spec {
                return Err(PapError::Conflict);
            }
            let current = state
                .binding_statuses
                .get(&id)
                .ok_or(PapError::Persistence)?;
            if *current != initial_status {
                return Err(PapError::Conflict);
            }
            return Ok(BindingView {
                spec: existing.clone(),
                status: *current,
            });
        }

        if next_raw_revision(state.binding_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.binding_specs.insert(key, spec.clone());
        state.binding_heads.insert(id.clone(), revision);
        state.binding_statuses.insert(id, initial_status);
        Ok(BindingView {
            spec: spec.clone(),
            status: initial_status,
        })
    }

    fn update_binding_status(
        &self,
        id: &ResourceId,
        binding_revision: Revision,
        expected_status: BindingStatus,
        next_status: BindingStatus,
    ) -> Result<BindingStatus, PapError> {
        let mut state = self.lock()?;
        let id = id.as_str().to_owned();
        if state.binding_heads.get(&id).copied() != Some(binding_revision.get()) {
            return Err(PapError::Conflict);
        }
        let current = state.binding_statuses.get(&id).ok_or(PapError::NotFound)?;
        if *current != expected_status {
            return Err(PapError::Conflict);
        }
        expected_status
            .validate_successor(next_status)
            .map_err(|_| PapError::Conflict)?;
        state.binding_statuses.insert(id, next_status);
        Ok(next_status)
    }

    fn get_binding_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<BindingRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.binding_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let status = state
            .binding_statuses
            .get(id.as_str())
            .copied()
            .ok_or(PapError::Persistence)?;
        Ok(Some(BindingRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            status,
        }))
    }

    fn get_binding_spec(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedBinding, PapError> {
        self.lock()?
            .binding_specs
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        let state = self.lock()?;
        binding_view(&state, id.as_str())
    }

    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        let state = self.lock()?;
        let items = state
            .binding_statuses
            .keys()
            .map(|id| binding_view(&state, id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(page(items, limit, offset))
    }
}

fn binding_view(state: &FakeState, id: &str) -> Result<BindingView, PapError> {
    let status = state
        .binding_statuses
        .get(id)
        .copied()
        .ok_or(PapError::NotFound)?;
    let revision = state
        .binding_heads
        .get(id)
        .copied()
        .ok_or(PapError::Persistence)?;
    let spec = state
        .binding_specs
        .get(&(id.to_owned(), revision))
        .cloned()
        .ok_or(PapError::Persistence)?;
    Ok(BindingView { spec, status })
}

struct FixtureCompiler {
    mismatch_identity: bool,
}

impl PolicyCompiler for FixtureCompiler {
    fn lower(&self, template: &TemplateEnvelope) -> Result<PolicyEnvelope, ValidationError> {
        let fixture: PreparedBinding = serde_json::from_str(COMPLETE_BINDING)
            .map_err(|error| ValidationError::new("fixture", error.to_string()))?;
        let mut policy = fixture.policy.canonical_policy;
        policy.policy_id = if self.mismatch_identity {
            PolicyId::new("compiler-mismatch")
                .map_err(|error| ValidationError::new("policyId", error))?
        } else {
            template.policy_id.clone()
        };
        policy.revision = template.revision;
        Ok(policy)
    }
}

type Service = PapService<FakeRepository, FixtureCompiler>;

fn service() -> (Service, Arc<FakeRepository>) {
    let repository = Arc::new(FakeRepository::default());
    let compiler = Arc::new(FixtureCompiler {
        mismatch_identity: false,
    });
    (
        PapService::new(Arc::clone(&repository), compiler),
        repository,
    )
}

fn policy_template(path: &str) -> PolicyTemplate {
    PolicyTemplate::PreventFileDeletion {
        files: vec![path.to_owned()],
    }
}

#[test]
fn policy_crud_is_idempotent_and_never_reuses_deleted_revisions() {
    let (pap, _) = service();
    let first = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    assert_eq!(first.revision.get(), 1);
    assert_eq!(
        pap.update_policy(
            &first.policy_id,
            "protect files",
            &policy_template("/workspace/a")
        )
        .unwrap(),
        first
    );

    let second = pap
        .update_policy(
            &first.policy_id,
            "protect more files",
            &policy_template("/workspace/b"),
        )
        .unwrap();
    assert_eq!(second.revision.get(), 2);
    assert_eq!(pap.list_policies(100, 0).unwrap().total, 2);
    assert_eq!(
        pap.delete_policy_revision(&first.policy_id, second.revision)
            .unwrap(),
        second
    );

    let third = pap
        .update_policy(
            &first.policy_id,
            "protect newest files",
            &policy_template("/workspace/c"),
        )
        .unwrap();
    assert_eq!(third.revision.get(), 3);
    assert_eq!(
        pap.get_policy(&first.policy_id, first.revision).unwrap(),
        first
    );
    assert_eq!(pap.list_policies(100, 0).unwrap().total, 2);
    let missing = ResourceId::new("missing-policy").unwrap();
    assert_eq!(
        pap.update_policy(&missing, "missing", &policy_template("/workspace/missing")),
        Err(PapError::NotFound)
    );
}

#[test]
fn scope_crud_validates_authored_selectors_and_preserves_revision_heads() {
    let (pap, _) = service();
    let first = pap.create_scope(&ScopeSelector::Pid { pid: 4242 }).unwrap();
    assert_eq!(first.revision.get(), 1);
    assert_eq!(
        pap.update_scope(&first.scope_id, &ScopeSelector::Pid { pid: 4242 })
            .unwrap(),
        first
    );

    let second = pap
        .update_scope(&first.scope_id, &ScopeSelector::CgroupId { cgroup_id: 99 })
        .unwrap();
    assert_eq!(second.revision.get(), 2);
    pap.delete_scope_revision(&first.scope_id, second.revision)
        .unwrap();
    let third = pap
        .update_scope(&first.scope_id, &ScopeSelector::Pid { pid: 7 })
        .unwrap();
    assert_eq!(third.revision.get(), 3);
    assert_eq!(pap.list_scopes(100, 0).unwrap().total, 2);

    let legacy = ScopeSelector::LegacyExecutionDomain {
        execution_domain_id: ResourceId::new("legacy-domain").unwrap(),
    };
    assert!(matches!(
        pap.create_scope(&legacy),
        Err(PapError::InvalidScope(_))
    ));
    let missing = ResourceId::new("missing-scope").unwrap();
    assert_eq!(
        pap.update_scope(&missing, &ScopeSelector::Pid { pid: 9 }),
        Err(PapError::NotFound)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end lifecycle scenario keeps transition assertions reviewable"
)]
fn binding_requests_advance_lifecycle_without_rewriting_specs() {
    let (pap, repository) = service();
    let policy_v1 = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    let scope = pap.create_scope(&ScopeSelector::Pid { pid: 4242 }).unwrap();
    let binding_v1 = pap
        .create_binding(
            &policy_v1.policy_id,
            policy_v1.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap();
    assert_eq!(binding_v1.spec.binding_revision.get(), 1);
    assert_eq!(binding_v1.status, BindingStatus::PendingApply);
    assert_eq!(
        pap.update_binding(
            &binding_v1.spec.binding_id,
            &policy_v1.policy_id,
            policy_v1.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap(),
        binding_v1
    );

    let policy_v2 = pap
        .update_policy(
            &policy_v1.policy_id,
            "protect more files",
            &policy_template("/workspace/b"),
        )
        .unwrap();
    let binding_v2 = pap
        .update_binding(
            &binding_v1.spec.binding_id,
            &policy_v2.policy_id,
            policy_v2.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap();
    assert_eq!(binding_v2.spec.binding_revision.get(), 2);
    assert_eq!(binding_v2.spec.policy, policy_v2);
    assert_eq!(binding_v2.status, BindingStatus::PendingApply);

    let pending_delete = pap.delete_binding(&binding_v1.spec.binding_id).unwrap();
    assert_eq!(pending_delete.spec.binding_revision.get(), 2);
    assert_eq!(pending_delete.status, BindingStatus::PendingDelete);
    let pending_delete_wire = serde_json::to_value(&pending_delete).unwrap();
    assert!(pending_delete_wire.get("lifecycle").is_none());
    assert_eq!(pending_delete_wire["status"], "PENDING_DELETE");
    assert!(pending_delete_wire["spec"].get("desiredState").is_none());
    assert_eq!(
        serde_json::from_value::<BindingView>(pending_delete_wire).unwrap(),
        pending_delete
    );
    assert_eq!(
        pap.delete_binding(&binding_v1.spec.binding_id).unwrap(),
        pending_delete
    );
    assert_eq!(
        pap.get_binding(&binding_v1.spec.binding_id).unwrap(),
        pending_delete
    );

    // Simulate the future worker claiming Delete. UPDATE of the same immutable
    // spec must reverse it instead of being mistaken for an idempotent no-op.
    let deleting = pending_delete.status.start_reconcile().unwrap();
    repository
        .update_binding_status(
            &pending_delete.spec.binding_id,
            pending_delete.spec.binding_revision,
            pending_delete.status,
            deleting,
        )
        .unwrap();
    let reactivated = pap
        .update_binding(
            &binding_v1.spec.binding_id,
            &policy_v2.policy_id,
            policy_v2.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap();
    assert_eq!(&reactivated.spec, &pending_delete.spec);
    assert_eq!(reactivated.status, BindingStatus::PendingApply);
    assert_eq!(
        repository.update_binding_status(
            &reactivated.spec.binding_id,
            Revision::new(1).unwrap(),
            reactivated.status,
            BindingStatus::Applying,
        ),
        Err(PapError::Conflict),
        "status CAS must target the current immutable spec revision"
    );

    // DELETED is not a legal successor of the newer PENDING_APPLY state. Full
    // asynchronous stale-result/ABA fencing remains part of the reconciler TODO.
    let stale_deleted = deleting.complete_reconcile().unwrap();
    assert_eq!(
        repository.update_binding_status(
            &reactivated.spec.binding_id,
            reactivated.spec.binding_revision,
            deleting,
            stale_deleted,
        ),
        Err(PapError::Conflict)
    );
    assert_eq!(
        pap.list_bindings(100, 0).unwrap().items,
        vec![reactivated.clone()]
    );

    {
        let state = repository.lock().unwrap();
        assert_eq!(
            state.binding_heads[&binding_v1.spec.binding_id.to_string()],
            2
        );
        assert_eq!(state.binding_specs.len(), 2);
    }

    let deleting_again = pap.delete_binding(&binding_v1.spec.binding_id).unwrap();
    assert_eq!(deleting_again.status, BindingStatus::PendingDelete);
    let changed_after_delete = pap
        .update_binding(
            &binding_v1.spec.binding_id,
            &policy_v1.policy_id,
            policy_v1.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap();
    assert_eq!(changed_after_delete.spec.binding_revision.get(), 3);
    assert_eq!(changed_after_delete.status, BindingStatus::PendingApply);

    let state = repository.lock().unwrap();
    assert_eq!(
        state.binding_heads[&binding_v1.spec.binding_id.to_string()],
        3
    );
    assert_eq!(state.binding_specs.len(), 3);
}

#[test]
fn binding_requires_exact_policy_and_scope_revisions() {
    let (pap, _) = service();
    let policy = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    let scope = pap.create_scope(&ScopeSelector::Pid { pid: 4242 }).unwrap();
    let missing = ResourceId::new("missing").unwrap();

    assert_eq!(
        pap.create_binding(
            &missing,
            Revision::new(1).unwrap(),
            &scope.scope_id,
            scope.revision,
        ),
        Err(PapError::NotFound)
    );
    assert_eq!(
        pap.create_binding(
            &policy.policy_id,
            policy.revision,
            &missing,
            Revision::new(1).unwrap(),
        ),
        Err(PapError::NotFound)
    );
    assert_eq!(
        pap.update_binding(
            &missing,
            &policy.policy_id,
            policy.revision,
            &scope.scope_id,
            scope.revision,
        ),
        Err(PapError::NotFound)
    );
}

#[test]
fn compiler_output_identity_is_checked_before_storage() {
    let repository = Arc::new(FakeRepository::default());
    let compiler = Arc::new(FixtureCompiler {
        mismatch_identity: true,
    });
    let pap = PapService::new(repository, compiler);

    let error = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap_err();
    let PapError::InvalidPolicy(error) = error else {
        panic!("expected invalid compiler output");
    };
    assert_eq!(error.path, "canonicalPolicy.policyId");
}

#[test]
fn revision_exhaustion_and_pagination_bounds_are_explicit() {
    let (pap, repository) = service();
    let first = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    let maximum = Revision::new(u32::MAX).unwrap();
    let mut exhausted = first.clone();
    exhausted.revision = maximum;
    exhausted.canonical_policy.revision = maximum;
    {
        let mut state = repository.lock().unwrap();
        state.policies.clear();
        state
            .policies
            .insert((first.policy_id.as_str().to_owned(), u32::MAX), exhausted);
        state
            .policy_heads
            .insert(first.policy_id.as_str().to_owned(), u32::MAX);
    }

    assert_eq!(
        pap.update_policy(
            &first.policy_id,
            "changed",
            &policy_template("/workspace/b"),
        ),
        Err(PapError::RevisionExhausted)
    );
    assert_eq!(pap.list_policies(0, 0), Err(PapError::InvalidPagination));
    assert_eq!(
        pap.list_policies(1_001, 0),
        Err(PapError::InvalidPagination)
    );
}

fn next_raw_revision(current: Option<u32>) -> Option<u32> {
    match current {
        Some(revision) => revision.checked_add(1),
        None => Some(1),
    }
}

fn page<T>(items: Vec<T>, limit: u32, offset: u32) -> Page<T> {
    let total = u64::try_from(items.len()).expect("test item count fits u64");
    let offset = usize::try_from(offset).expect("u32 offset fits usize");
    let limit = usize::try_from(limit).expect("u32 limit fits usize");
    Page {
        items: items.into_iter().skip(offset).take(limit).collect(),
        total,
    }
}

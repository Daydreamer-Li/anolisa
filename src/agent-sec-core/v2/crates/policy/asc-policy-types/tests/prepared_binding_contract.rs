use asc_policy_types::Validate;
use asc_policy_types::binding::PreparedBinding;
use asc_policy_types::identifiers::Revision;

const COMPLETE_BINDING: &str = include_str!("fixtures/prepared-binding.json");

fn prepared_binding() -> PreparedBinding {
    serde_json::from_str(COMPLETE_BINDING).expect("complete Binding fixture must deserialize")
}

#[test]
fn complete_binding_round_trips_and_validates_as_one_boundary_document() {
    let expected: serde_json::Value = serde_json::from_str(COMPLETE_BINDING).unwrap();
    let binding = prepared_binding();

    binding.validate().unwrap();
    assert_eq!(binding.binding_revision.get(), 7);
    assert_eq!(binding.policy.revision.get(), 1);
    assert_eq!(binding.scope.revision.get(), 3);
    assert_eq!(serde_json::to_value(binding).unwrap(), expected);
}

#[test]
fn binding_validation_rejects_inconsistent_embedded_policy_identity() {
    let mut binding = prepared_binding();
    binding.policy.canonical_policy.revision = Revision::new(2).unwrap();

    let error = binding.validate().unwrap_err();
    assert_eq!(error.path, "policy.canonicalPolicy.revision");
}

#[test]
fn binding_validation_addresses_invalid_scope_fields() {
    let mut binding: serde_json::Value = serde_json::from_str(COMPLETE_BINDING).unwrap();
    binding["scope"]["selector"]["pid"] = serde_json::json!(0);
    let binding: PreparedBinding = serde_json::from_value(binding).unwrap();

    let error = binding.validate().unwrap_err();
    assert_eq!(error.path, "scope.selector.pid");
}

#[test]
fn legacy_read_fields_are_not_reemitted_and_unknown_fields_are_rejected() {
    let mut legacy: serde_json::Value = serde_json::from_str(COMPLETE_BINDING).unwrap();
    legacy["policy"]["retired"] = serde_json::json!(false);
    legacy["scope"]["retired"] = serde_json::json!(false);
    legacy["executionDomainId"] = serde_json::json!("legacy-domain");

    let binding: PreparedBinding = serde_json::from_value(legacy).unwrap();
    let current = serde_json::to_value(binding).unwrap();
    assert!(current["policy"].get("retired").is_none());
    assert!(current["scope"].get("retired").is_none());
    assert!(current.get("executionDomainId").is_none());

    let mut unknown: serde_json::Value = serde_json::from_str(COMPLETE_BINDING).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreparedBinding>(unknown).is_err());
}

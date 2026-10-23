use super::*;
#[test]
fn caller_authority_overrides_and_plaintext_response_fields_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let req = SecretRequest2 {
        registration_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 1,
        operation: SecretOperation2::ResolveConfigMaster,
    };
    for field in [
        "subject",
        "backend_id",
        "slot",
        "sender",
        "permission",
        "key",
        "path",
    ] {
        let mut value = serde_json::to_value(&req)?;
        value[field] = serde_json::json!("caller-authority");
        assert!(serde_json::from_value::<SecretRequest2>(value).is_err());
    }
    let value = serde_json::to_value(SecretResponse2::MasterHandle {
        handle: "random-alias".into(),
        purpose: MasterPurpose2::ConfigUserMaster,
        generation: 1,
    })?;
    assert_eq!(value.as_object().ok_or("object")?.len(), 4);
    let mut forged = value;
    forged["bytes"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<SecretResponse2>(forged).is_err());
    assert!(
        !format!(
            "{:?}",
            SecretBackendLoadStatus2::Present {
                encoded: b"private-master".to_vec()
            }
        )
        .contains("private-master")
    );
    Ok(())
}

#[test]
fn runtime_secret_scope_registration_only_accepts_the_trusted_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    let request = RegisterSecretScopeRequest2 {
        registration: SecretRegistration2 {
            registration_id: "a".repeat(32),
            approval_scope_id: "b".repeat(32),
            origin: Origin::Operator,
            purpose: MasterPurpose2::ConfigUserMaster,
            target: SecretBinding2 {
                backend_id: "c".repeat(32),
                slot: MasterSlotKind2::User,
            },
            legacy: vec![],
        },
    };
    let value = serde_json::to_value(&request)?;
    assert_eq!(
        serde_json::from_value::<RegisterSecretScopeRequest2>(value.clone())?,
        request
    );
    let mut forged = value;
    forged["subject"] = serde_json::json!({ "user": "caller" });
    assert!(serde_json::from_value::<RegisterSecretScopeRequest2>(forged).is_err());
    let receipt = SecretScopeReceipt2 {
        registration_id: "a".repeat(32),
        active: true,
    };
    assert_eq!(
        serde_json::from_value::<SecretScopeReceipt2>(serde_json::to_value(receipt.clone())?)?,
        receipt
    );
    Ok(())
}

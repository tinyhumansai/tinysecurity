use super::*;
#[test]
fn scoped_debug_is_content_free_even_when_nested() {
    let subject = SubjectScope {
        user: "private-user-needle".into(),
        workspace: "private-workspace-needle".into(),
        agent: "private-agent-needle".into(),
    };
    let header = EgressHeader {
        name: "private-header-name".into(),
        value: "private-header-value".into(),
    };
    let request = ScopedEgressRequest {
        policy_id: EgressPolicyId("private-policy-id".into()),
        subject: subject.clone(),
        tier: crate::AccessTier::Full,
        url: "https://private-url-needle.example/private-query".into(),
        method: "POST".into(),
        category: DataCategory::UserContent,
        payload: "private-body-needle".into(),
        headers: vec![header.clone()],
        transport: EgressTransport::PinnedDirect,
        local_capability: None,
        transformation: Some("private-transform-needle".into()),
    };
    let auth = TransportAuthorization {
        fingerprint: "private-fingerprint".into(),
        authorization_id: "private-auth-id".into(),
        url: request.url.clone(),
        hostname: "private-hostname".into(),
        port: 443,
        addresses: vec![],
        subject: subject.clone(),
        policy_id: request.policy_id.clone(),
        generation: 1,
        expires_at_ms: 42,
    };
    assert_eq!(format!("{header:?}"), "EgressHeader([REDACTED])");
    assert_eq!(format!("{request:?}"), "ScopedEgressRequest([REDACTED])");
    assert_eq!(format!("{auth:?}"), "TransportAuthorization([REDACTED])");
    let response = ScopedEgressResponse {
        generation: 1,
        denial: None,
        authorization: Some(auth.clone()),
        cacheable: false,
    };
    let consume = ConsumeEgressAuthorizationRequest {
        request,
        subject,
        authorization: auth,
    };
    for output in [
        format!("{response:?}"),
        format!("{consume:?}"),
        format!("{consume:#?}"),
    ] {
        assert!(!output.contains("private-"), "{output}");
    }
}

#[test]
/// Browser authorization payloads expose no page identity or fabricated HTTP data.
fn browser_dial_contract_redacts_identity_and_serializes_no_http_payload()
-> Result<(), serde_json::Error> {
    let subject = SubjectScope {
        user: "private-user".into(),
        workspace: "private-workspace".into(),
        agent: "private-agent".into(),
    };
    let request = BrowserDialRequest {
        policy_id: EgressPolicyId("private-policy".into()),
        expected_generation: 9,
        session_id: "browser-session-private".into(),
        scheme: "https".into(),
        hostname: "private-destination.example".into(),
        port: 443,
    };
    let json = serde_json::to_value(&request)?;
    assert!(json.get("method").is_none());
    assert!(json.get("headers").is_none());
    assert!(json.get("payload").is_none());
    assert_eq!(format!("{request:?}"), "BrowserDialRequest([REDACTED])");
    let authorization = BrowserDialAuthorization {
        authorization_id: "private-nonce".into(),
        session_id: request.session_id.clone(),
        scheme: "https".into(),
        hostname: "private-destination.example".into(),
        port: 443,
        addresses: vec![std::net::SocketAddr::from(([8, 8, 8, 8], 443))],
        subject: subject.clone(),
        policy_id: request.policy_id.clone(),
        generation: 7,
        expires_at_ms: 10_000,
    };
    assert!(!format!("{authorization:?}").contains("private-"));
    let validate = ValidateBrowserDialRequest {
        authorization: authorization.clone(),
    };
    assert_eq!(
        format!("{validate:?}"),
        "ValidateBrowserDialRequest([REDACTED])"
    );
    let consume = ConsumeBrowserDialRequest {
        request,
        address: authorization.addresses[0],
        authorization,
    };
    assert!(!format!("{consume:#?}").contains("private-"));
    Ok(())
}

#[test]
/// Pins the destination-only request wire shape, including its policy generation.
fn browser_dial_request_has_exact_wire_shape() -> Result<(), serde_json::Error> {
    let request = browser_wire_request();
    assert_wire_shape(
        &request,
        serde_json::json!({
            "policy_id": "policy-1",
            "expected_generation": 7,
            "session_id": "session-1",
            "scheme": "https",
            "hostname": "example.com",
            "port": 443
        }),
    )
}

#[test]
/// Pins the authorization fields needed to dial only an approved socket.
fn browser_dial_authorization_has_exact_wire_shape() -> Result<(), serde_json::Error> {
    assert_wire_shape(
        &browser_wire_authorization(),
        serde_json::json!({
            "authorization_id": "nonce-1",
            "session_id": "session-1",
            "scheme": "https",
            "hostname": "example.com",
            "port": 443,
            "addresses": ["8.8.8.8:443"],
            "subject": {"user": "user", "workspace": "workspace", "agent": "agent"},
            "policy_id": "policy-1",
            "generation": 7,
            "expires_at_ms": 30042
        }),
    )
}

#[test]
/// Pins the success response shape returned by browser destination authorization.
fn browser_dial_response_has_exact_wire_shape() -> Result<(), serde_json::Error> {
    let response = BrowserDialResponse {
        generation: 7,
        denial: None,
        authorization: Some(browser_wire_authorization()),
    };
    assert_wire_shape(
        &response,
        serde_json::json!({
            "generation": 7,
            "denial": null,
            "authorization": browser_wire_authorization()
        }),
    )
}

#[test]
/// Pins the exact request shape for consuming a browser socket grant.
fn browser_dial_consume_request_has_exact_wire_shape() -> Result<(), serde_json::Error> {
    let request = browser_wire_request();
    let authorization = browser_wire_authorization();
    let consume = ConsumeBrowserDialRequest {
        request: request.clone(),
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    assert_wire_shape(
        &consume,
        serde_json::json!({
            "request": request,
            "address": "8.8.8.8:443",
            "authorization": authorization
        }),
    )
}

#[test]
/// Pins the exact request shape for validating an open browser tunnel lease.
fn browser_dial_validate_request_has_exact_wire_shape() -> Result<(), serde_json::Error> {
    let request = ValidateBrowserDialRequest {
        authorization: browser_wire_authorization(),
    };
    assert_wire_shape(
        &request,
        serde_json::json!({"authorization": browser_wire_authorization()}),
    )
}

#[test]
/// Prevents accidental wire renames for browser traffic and stale denials.
fn browser_dial_enum_values_have_stable_wire_names() -> Result<(), serde_json::Error> {
    assert_eq!(
        serde_json::to_value(DataCategory::OpaqueBrowserTraffic)?,
        "opaque_browser_traffic"
    );
    assert_eq!(serde_json::to_value(EgressDenial::Stale)?, "stale");
    Ok(())
}

/// Construct a representative authorization with a single approved socket.
fn browser_wire_authorization() -> BrowserDialAuthorization {
    BrowserDialAuthorization {
        authorization_id: "nonce-1".into(),
        session_id: "session-1".into(),
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        addresses: vec![std::net::SocketAddr::from(([8, 8, 8, 8], 443))],
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_id: EgressPolicyId("policy-1".into()),
        generation: 7,
        expires_at_ms: 30_042,
    }
}

/// Construct a representative destination-only browser request.
fn browser_wire_request() -> BrowserDialRequest {
    BrowserDialRequest {
        policy_id: EgressPolicyId("policy-1".into()),
        expected_generation: 7,
        session_id: "session-1".into(),
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
    }
}

/// Pin both serialization and deserialization of one browser-dial contract type.
fn assert_wire_shape<T>(value: &T, expected: serde_json::Value) -> Result<(), serde_json::Error>
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    assert_eq!(serde_json::to_value(value)?, expected);
    assert_eq!(serde_json::from_value::<T>(expected)?, *value);
    Ok(())
}

use super::*;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tinysecurity_bus::{
    AccessTier, BrowserDialRequest, ConsumeBrowserDialRequest, DataCategory, DestinationRule,
    LocalEgressCapability, PrivacyMode, ValidateBrowserDialRequest,
};
#[derive(Debug)]
struct Clock;
impl EgressClock for Clock {
    fn now_ms(&self) -> u64 {
        42
    }
}
#[derive(Debug)]
struct Dns {
    calls: AtomicUsize,
    answers: Vec<IpAddr>,
}
impl Resolver for Dns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}
fn owner() -> SubjectScope {
    SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    }
}
fn policy() -> EgressPolicy {
    EgressPolicy {
        owner: owner(),
        ceiling: AccessTier::Full,
        privacy: PrivacyMode::Standard,
        destinations: vec![DestinationRule {
            scheme: "https".into(),
            hostname: "example.com".into(),
            port: 8443,
            include_subdomains: true,
        }],
        data_categories: vec![DataCategory::UserContent, DataCategory::HostMetadata],
        local_capabilities: vec![],
        validity_ms: 1000,
        open_public: false,
        preflight_transports: vec![],
    }
}
fn request(id: EgressPolicyId) -> ScopedEgressRequest {
    ScopedEgressRequest {
        policy_id: id,
        subject: owner(),
        tier: AccessTier::Full,
        url: "https://Example.COM:8443/a%20b?q=1".into(),
        method: "POST".into(),
        category: DataCategory::UserContent,
        payload: "ordinary content".into(),
        headers: vec![],
        transport: EgressTransport::PinnedDirect,
        local_capability: None,
        transformation: None,
    }
}
/// Make a valid browser destination request for a registered policy.
fn browser_request(id: EgressPolicyId) -> BrowserDialRequest {
    BrowserDialRequest {
        policy_id: id,
        expected_generation: 1,
        session_id: "browser-session-1".into(),
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
    }
}
#[derive(Debug)]
struct Failed;
impl Resolver for Failed {
    fn resolve(
        &self,
        _: &str,
        timeout: Duration,
        limit: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        assert_eq!(timeout, Duration::from_secs(2));
        assert_eq!(limit, 64);
        Err(crate::ResolveFailure)
    }
}
#[test]
fn url_guard_returns_scoped_exact_vetted_transport_authorization()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?, "2606:4700:4700::1111".parse()?],
    };
    let result = registry
        .get_owned(&id)?
        .check(&request(id.clone()), 7, &dns);
    assert_eq!(result.denial, None);
    assert!(!result.cacheable);
    let auth = result.authorization.ok_or("missing authorization")?;
    assert_eq!(auth.hostname, "example.com");
    assert_eq!(auth.port, 8443);
    assert_eq!(auth.addresses.len(), 2);
    assert_eq!(auth.subject, owner());
    assert_eq!(auth.policy_id, id);
    assert_eq!(auth.generation, 7);
    assert_eq!(auth.expires_at_ms, 1042);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[test]
/// Grants include every resolved public socket and can be consumed only once.
fn browser_dial_returns_exact_resolved_sockets_and_consumes_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.destinations = vec![DestinationRule {
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        include_subdomains: false,
    }];
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(configured)?;
    registry.advance_generation(7)?;
    let resolver = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?, "2606:4700:4700::1111".parse()?],
    };
    let mut request = browser_request(id.clone());
    request.expected_generation = 7;
    let result = registry
        .get_owned(&id)?
        .authorize_browser_dial(&request, 7, &resolver);
    assert_eq!(result.denial, None);
    let authorization = result.authorization.ok_or("missing dial grant")?;
    assert_eq!(authorization.hostname, "example.com");
    assert_eq!(authorization.scheme, "https");
    assert_eq!(authorization.port, 443);
    assert_eq!(authorization.addresses.len(), 2);
    assert_eq!(authorization.generation, 7);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    let consume = ConsumeBrowserDialRequest {
        request: request.clone(),
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    let policy = registry.get_owned(&id)?;
    assert!(policy.consume_browser_dial(&consume, 7));
    assert!(!policy.consume_browser_dial(&consume, 7));
    let lease = ValidateBrowserDialRequest { authorization };
    assert!(policy.validate_browser_dial(&lease, 7));
    registry.advance_generation(8)?;
    assert!(!policy.validate_browser_dial(&lease, 8));
    Ok(())
}
#[derive(Debug)]
struct RetentionRaceClock(AtomicUsize);
impl EgressClock for RetentionRaceClock {
    fn now_ms(&self) -> u64 {
        match self.0.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => 100,
            _ => 101,
        }
    }
}
#[test]
/// Rejects authorizations that expire before DNS results can be retained.
fn browser_dial_rejects_grant_expired_before_retention()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.validity_ms = 1;
    configured.destinations = vec![DestinationRule {
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        include_subdomains: false,
    }];
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry =
        EgressPolicyRegistry::with_clock(Arc::new(RetentionRaceClock(AtomicUsize::new(0))));
    let id = registry.register(configured)?;
    registry.advance_generation(1)?;
    let resolver = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };

    let response =
        registry
            .get_owned(&id)?
            .authorize_browser_dial(&browser_request(id), 1, &resolver);

    assert_eq!(response.denial, Some(EgressDenial::Stale));
    assert_eq!(response.authorization, None);
    Ok(())
}
#[test]
/// Browser authorization rejects private answers and opaque data in restrictive modes.
fn browser_dial_denies_private_dns_answers_and_sensitive_opaque_traffic()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.open_public = true;
    configured.destinations.clear();
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(configured.clone())?;
    let request = browser_request(id.clone());
    let private_dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["169.254.169.254".parse()?],
    };
    assert_eq!(
        registry
            .get_owned(&id)?
            .authorize_browser_dial(
                &BrowserDialRequest {
                    expected_generation: 2,
                    session_id: request.session_id.clone(),
                    ..request.clone()
                },
                1,
                &private_dns
            )
            .denial,
        Some(EgressDenial::Stale)
    );
    assert_eq!(
        registry
            .get_owned(&id)?
            .authorize_browser_dial(&request, 1, &private_dns)
            .denial,
        Some(EgressDenial::Address)
    );

    configured.privacy = PrivacyMode::Sensitive;
    let mut sensitive_registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let sensitive_id = sensitive_registry.register(configured)?;
    let public_dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    assert_eq!(
        sensitive_registry
            .get_owned(&sensitive_id)?
            .authorize_browser_dial(&browser_request(sensitive_id), 1, &public_dns)
            .denial,
        Some(EgressDenial::Privacy)
    );
    Ok(())
}

#[test]
/// Public IPv6 literals are preserved as exact dial targets.
fn browser_dial_accepts_canonical_public_ipv6_literal()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.destinations = vec![DestinationRule {
        scheme: "https".into(),
        hostname: "2606:4700:4700::1111".into(),
        port: 443,
        include_subdomains: false,
    }];
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(configured)?;
    let request = BrowserDialRequest {
        policy_id: id.clone(),
        expected_generation: 1,
        session_id: "browser-session-v6".into(),
        scheme: "https".into(),
        hostname: "2606:4700:4700::1111".into(),
        port: 443,
    };
    let result = registry.get_owned(&id)?.authorize_browser_dial(
        &request,
        1,
        &Dns {
            calls: AtomicUsize::new(0),
            answers: Vec::new(),
        },
    );
    assert_eq!(result.denial, None);
    assert_eq!(
        result.authorization.ok_or("missing grant")?.addresses,
        vec!["[2606:4700:4700::1111]:443".parse()?]
    );
    Ok(())
}

#[test]
/// Live browser leases have a fixed capacity and do not evict active grants.
fn live_browser_dial_leases_are_bounded() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.open_public = true;
    configured.destinations.clear();
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(configured)?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    for _ in 0..256 {
        let request = browser_request(id.clone());
        let grant = scope
            .authorize_browser_dial(&request, 1, &dns)
            .authorization
            .ok_or("grant denied")?;
        let consume = ConsumeBrowserDialRequest {
            request,
            address: grant.addresses[0],
            authorization: grant,
        };
        assert!(scope.consume_browser_dial(&consume, 1));
    }
    assert!(
        scope
            .authorize_browser_dial(&browser_request(id), 1, &dns)
            .authorization
            .is_none()
    );
    Ok(())
}
#[test]
/// Grants cannot be replayed across sessions, destinations, policies, or generations.
fn browser_dial_grants_bind_scope_destination_and_generation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut configured = policy();
    configured.open_public = true;
    configured.destinations.clear();
    configured
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(configured)?;
    let request = browser_request(id.clone());
    let resolver = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let policy = registry.get_owned(&id)?;
    let authorization = policy
        .authorize_browser_dial(&request, 1, &resolver)
        .authorization
        .ok_or("missing dial grant")?;
    let wrong_destination = ConsumeBrowserDialRequest {
        request: BrowserDialRequest {
            hostname: "other.example".into(),
            ..request.clone()
        },
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    assert!(!policy.consume_browser_dial(&wrong_destination, 1));
    let wrong_generation = ConsumeBrowserDialRequest {
        request: BrowserDialRequest {
            expected_generation: 2,
            ..request.clone()
        },
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    assert!(!policy.consume_browser_dial(&wrong_generation, 1));
    let wrong_session = ConsumeBrowserDialRequest {
        request: BrowserDialRequest {
            session_id: "different-browser-session".into(),
            ..request.clone()
        },
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    assert!(!policy.consume_browser_dial(&wrong_session, 1));
    let valid = ConsumeBrowserDialRequest {
        request: request.clone(),
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    assert!(policy.consume_browser_dial(&valid, 1));
    registry.advance_generation(2)?;
    let stale = ConsumeBrowserDialRequest {
        request,
        address: authorization.addresses[0],
        authorization,
    };
    assert!(!policy.consume_browser_dial(&stale, 2));
    Ok(())
}
#[test]
fn invalid_registration_is_atomic_and_scopes_are_isolated()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let mut invalid = policy();
    invalid.destinations[0].hostname = "*.example.com".into();
    assert!(registry.register(invalid).is_err());
    let mut second = policy();
    second.owner.user = "other".into();
    let second_id = registry.register(second)?;
    assert_ne!(id, second_id);
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id.clone());
    req.subject.user = "other".into();
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Scope)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    assert!(
        registry
            .get_owned(&EgressPolicyId("unknown".into()))
            .is_err()
    );
    Ok(())
}
#[test]
fn url_guard_denies_any_forbidden_dns_candidate_and_bounded_failures()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    for ips in [
        vec!["8.8.8.8", "10.0.0.1"],
        vec!["fd00::1", "8.8.8.8"],
        vec![],
        vec!["8.8.8.8"; 65],
    ] {
        let dns = Dns {
            calls: AtomicUsize::new(0),
            answers: ips
                .iter()
                .map(|ip| ip.parse())
                .collect::<std::result::Result<_, _>>()?,
        };
        assert!(scope.check(&request(id.clone()), 1, &dns).denial.is_some());
    }
    assert_eq!(
        scope.check(&request(id.clone()), 1, &Failed).denial,
        Some(EgressDenial::Resolver)
    );
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?; 3],
    };
    assert_eq!(
        scope
            .check(&request(id), 1, &dns)
            .authorization
            .ok_or("missing")?
            .addresses
            .len(),
        1
    );
    Ok(())
}
#[test]
fn local_only_blocks_all_external_routes_before_dns_and_local_capability_is_narrow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::LocalOnly;
    config.local_capabilities.push(LocalEgressCapability {
        origin: "http://127.0.0.1:11434".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    });
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id);
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Privacy)
    );
    req.local_capability = Some(0);
    assert!(scope.check(&req, 1, &dns).denial.is_some());
    req.url = "http://127.0.0.1:11434/health".into();
    req.category = DataCategory::HostMetadata;
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    for url in [
        "http://127.0.0.1:11434/api/chat",
        "http://127.0.0.1:11434/health?q=x",
        "http://127.0.0.1:11434/health#x",
        "http://169.254.169.254:11434/health",
    ] {
        req.url = url.into();
        assert!(scope.check(&req, 1, &dns).denial.is_some());
    }
    req.url = "http://127.0.0.1:11434/health".into();
    req.local_capability = None;
    assert!(scope.check(&req, 1, &dns).denial.is_some());
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn standard_and_sensitive_enforce_original_data_and_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    for category in [
        DataCategory::Unknown,
        DataCategory::Credentials,
        DataCategory::Identifiers,
    ] {
        req.category = category;
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.category = DataCategory::UserContent;
    for payload in [
        "bearer raw-private-token",
        "email me at person@example.com",
        "{\"password\":\"raw-secret\"}",
    ] {
        req.payload = payload.into();
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.payload = "ordinary content".into();
    req.transformation = Some("fake-approved".into());
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Privacy)
    );
    req.transformation = None;
    req.url = "https://evil-example.com:8443/".into();
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Destination)
    );
    for transport in [
        EgressTransport::Browser,
        EgressTransport::Proxy,
        EgressTransport::Unsupported,
    ] {
        req.transport = transport;
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Transport)
        );
    }
    Ok(())
}

#[test]
/// Sensitive legacy egress denies opaque browser traffic before DNS resolution.
fn sensitive_privacy_rejects_opaque_browser_traffic_on_legacy_scoped_egress()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    config
        .data_categories
        .push(DataCategory::OpaqueBrowserTraffic);
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(config)?;
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    req.category = DataCategory::OpaqueBrowserTraffic;

    assert_eq!(
        registry
            .get_owned(&req.policy_id)?
            .check(&req, 1, &dns)
            .denial,
        Some(EgressDenial::Privacy)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[derive(Debug)]
struct MutableClock(std::sync::atomic::AtomicU64);
impl EgressClock for MutableClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[test]
fn lease_expires_and_clock_rollback_cannot_extend_permission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let clock = Arc::new(MutableClock(std::sync::atomic::AtomicU64::new(1000)));
    let mut registry = EgressPolicyRegistry::with_clock(clock.clone());
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let req = request(id);
    let auth = scope.check(&req, 7, &dns).authorization.ok_or("missing")?;
    assert!(scope.valid(&auth, &owner(), 7));
    assert!(!scope.valid(&auth, &owner(), 8));
    clock.0.store(2000, Ordering::SeqCst);
    assert!(!scope.valid(&auth, &owner(), 7));
    clock.0.store(1000, Ordering::SeqCst);
    assert!(!scope.valid(&auth, &owner(), 7));
    assert_eq!(scope.check(&req, 7, &dns).denial, Some(EgressDenial::Stale));
    Ok(())
}
#[test]
fn lease_validation_rejects_tampered_addresses_or_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut auth = scope
        .check(&request(id), 7, &dns)
        .authorization
        .ok_or("missing")?;
    auth.addresses = vec!["127.0.0.1:8443".parse()?];
    assert!(!scope.valid(&auth, &owner(), 7));
    Ok(())
}
#[test]
fn consume_is_exact_once_and_replayed_grants_deny()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let auth = scope
        .check(&request(id), 7, &dns)
        .authorization
        .ok_or("missing")?;
    let mut other = owner();
    other.agent = "other-agent".into();
    assert!(!scope.consume(&auth, &other, 7));
    assert!(!scope.consume(&auth, &owner(), 8));
    assert!(scope.consume(&auth, &owner(), 7));
    assert!(!scope.consume(&auth, &owner(), 7));
    assert!(!scope.valid(&auth, &owner(), 7));
    Ok(())
}
#[test]
fn privacy_and_address_floor_cannot_be_overridden_by_configured_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    for hostname in [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "*",
        "*.example.com",
        "[::1]",
    ] {
        let mut bad = policy();
        bad.destinations[0].hostname = hostname.into();
        assert!(registry.register(bad).is_err());
    }
    let mut config = policy();
    config.destinations.clear();
    let id = registry.register(config)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id.clone());
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Destination)
    );
    req.url = "http://127.0.0.1/".into();
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Address)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn generic_url_guard_cannot_use_narrow_host_local_capability()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.local_capabilities.push(LocalEgressCapability {
        origin: "http://127.0.0.1:11434".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    });
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.category = DataCategory::HostMetadata;
    req.local_capability = Some(0);
    req.url = "http://127.0.0.1:11434/health".into();
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec![],
    };
    let redactor = Redactor::new(&RedactorConfig::default())?;
    assert_eq!(
        scope.url_guard(&req, 1, &dns, &redactor).denial,
        Some(EgressDenial::Address)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn sensitive_inspects_original_url_headers_and_payload_before_dns()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    for url in [
        "https://example.com:8443/path?api_key=raw-private-token",
        "https://example.com:8443/path#person@example.com",
        "https://example.com:8443/person%40example.com",
    ] {
        req.url = url.into();
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.url = "https://example.com:8443/path".into();
    for (name, value) in [
        ("Authorization", "Bearer raw-token"),
        ("X-User-Id", "opaque-identifier"),
        ("X-Comment", "person@example.com"),
        ("Host", "127.0.0.1"),
        ("X-Test", "line\r\nHost: evil"),
    ] {
        req.headers = vec![tinysecurity_bus::EgressHeader {
            name: name.into(),
            value: value.into(),
        }];
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    req.headers = vec![tinysecurity_bus::EgressHeader {
        name: "User-Agent".into(),
        value: "fixture".into(),
    }];
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    Ok(())
}
#[test]
fn actual_outgoing_operation_changes_invalidate_the_grant()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let req = request(id);
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let auth = scope.check(&req, 7, &dns).authorization.ok_or("missing")?;
    let mut changed = req.clone();
    changed.payload = "different body".into();
    assert!(!scope.consume_request(&changed, &auth, &owner(), 7));
    changed = req.clone();
    changed.headers = vec![tinysecurity_bus::EgressHeader {
        name: "Authorization".into(),
        value: "Bearer private-token".into(),
    }];
    assert!(!scope.consume_request(&changed, &auth, &owner(), 7));
    for (url, method) in [
        ("https://example.com:8443/a%20b?q=1", "POST"),
        (req.url.as_str(), "PUT"),
    ] {
        changed = req.clone();
        changed.url = url.into();
        changed.method = method.into();
        assert!(!scope.consume_request(&changed, &auth, &owner(), 7));
    }
    assert!(scope.consume_request(&req, &auth, &owner(), 7));
    Ok(())
}

#[test]
fn reserved_protocol_addresses_cannot_be_allowlisted_or_mixed_into_dns()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    for ip in [
        "2001:10::1",
        "2001:1f:ffff::1",
        "2001:20::1",
        "2001:2f:ffff::1",
        "2001:1::4",
        "2001:1ff::1",
    ] {
        let mut config = policy();
        config.destinations[0].hostname = ip.into();
        config.destinations[0].include_subdomains = false;
        assert!(registry.register(config).is_err(), "{ip}");
        let mut req = request(id.clone());
        req.url = format!("https://[{ip}]:8443/");
        assert_eq!(
            scope.check(&req, 1, &Failed).denial,
            Some(EgressDenial::Address)
        );
        for answers in [vec![ip, "8.8.8.8"], vec!["8.8.8.8", ip]] {
            let dns = Dns {
                calls: AtomicUsize::new(0),
                answers: answers
                    .into_iter()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()?,
            };
            assert_eq!(
                scope.check(&request(id.clone()), 1, &dns).denial,
                Some(EgressDenial::Address)
            );
        }
    }
    Ok(())
}
#[derive(Debug)]
struct PausedDns {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}
impl Resolver for PausedDns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        self.entered.wait();
        self.release.wait();
        Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))])
    }
}
#[test]
fn late_old_generation_dns_cannot_revoke_new_generation_grants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let req = request(id);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let old_scope = scope.clone();
    let old_req = req.clone();
    let dns = PausedDns {
        entered: entered.clone(),
        release: release.clone(),
    };
    let pending = std::thread::spawn(move || old_scope.check(&old_req, 1, &dns));
    entered.wait();
    registry.advance_generation(2)?;
    let current = scope
        .check(
            &req,
            2,
            &Dns {
                calls: AtomicUsize::new(0),
                answers: vec!["8.8.8.8".parse()?],
            },
        )
        .authorization
        .ok_or("current missing")?;
    release.wait();
    let old = pending.join().map_err(|_| "old resolver panicked")?;
    assert_eq!(old.denial, Some(EgressDenial::Stale));
    assert!(scope.consume_request(&req, &current, &owner(), 2));
    assert!(!scope.consume_request(&req, &current, &owner(), 2));
    Ok(())
}
#[test]
fn sensitive_inspects_decoded_form_body_and_refuses_unsupported_codings()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    let redactor = Redactor::new(&RedactorConfig {
        secrets: vec![tinysecurity_bus::Secret("exact-private-credential".into())],
    })?;
    for content_type in [
        "application/x-www-form-urlencoded",
        "Application/X-WWW-Form-Urlencoded; Charset=UTF-8",
    ] {
        req.headers = vec![tinysecurity_bus::EgressHeader {
            name: "cOnTeNt-TyPe".into(),
            value: content_type.into(),
        }];
        for body in [
            "email=person%40example.com",
            "name=person%40example.com+extra",
            "data=exact%2dprivate%2dcredential",
            "email=%FF",
            "value=%",
            "value=%0G",
        ] {
            req.payload = body.into();
            assert_eq!(
                scope
                    .check_with_redactor(&req, 1, &Failed, &redactor)
                    .denial,
                Some(EgressDenial::Privacy),
                "{body}"
            );
        }
        req.payload = "message=ordinary+content&count=42&value=%E2%9C%93".into();
        assert_eq!(
            scope
                .check_with_redactor(
                    &req,
                    1,
                    &Dns {
                        calls: AtomicUsize::new(0),
                        answers: vec!["8.8.8.8".parse()?]
                    },
                    &redactor
                )
                .denial,
            None
        );
    }
    for (name, value) in [
        ("Content-Encoding", "gzip"),
        ("Content-Encoding", "br"),
        ("Content-Type", "application/octet-stream"),
        (
            "Content-Type",
            "application/x-www-form-urlencoded; charset=iso-8859-1",
        ),
    ] {
        req.headers = vec![tinysecurity_bus::EgressHeader {
            name: name.into(),
            value: value.into(),
        }];
        req.payload = "ordinary".into();
        assert_eq!(
            scope.check(&req, 1, &Failed).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.headers = vec![
        tinysecurity_bus::EgressHeader {
            name: "Content-Type".into(),
            value: "text/plain".into()
        };
        2
    ];
    assert_eq!(
        scope.check(&req, 1, &Failed).denial,
        Some(EgressDenial::Privacy)
    );
    Ok(())
}
#[test]
fn fingerprint_rejects_oversized_operations_before_serializing() {
    let req = request(EgressPolicyId("test".into()));
    let mut body = req.clone();
    body.payload = "x".repeat(65_537);
    let mut url = req.clone();
    url.url = "x".repeat(8193);
    let mut headers = req.clone();
    headers.headers = vec![
        tinysecurity_bus::EgressHeader {
            name: "X".into(),
            value: "x".into()
        };
        65
    ];
    let mut aggregate = req;
    aggregate.headers = vec![
        tinysecurity_bus::EgressHeader {
            name: "X".into(),
            value: "x".repeat(4096)
        };
        4
    ];
    for invalid in [body, url, headers, aggregate] {
        assert!(fingerprint(&invalid).is_err());
    }
}

#[test]
fn activation_revokes_old_leases_even_without_new_generation_issuance()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let req = request(id);
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let old = scope
        .check(&req, 1, &dns)
        .authorization
        .ok_or("missing old")?;
    registry.advance_generation(2)?;
    assert!(!scope.consume_request(&req, &old, &owner(), 1));
    assert_eq!(scope.check(&req, 1, &dns).denial, Some(EgressDenial::Stale));
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    assert!(registry.advance_generation(1).is_err());
    let new = scope
        .check(&req, 2, &dns)
        .authorization
        .ok_or("missing new")?;
    assert!(scope.consume_request(&req, &new, &owner(), 2));
    Ok(())
}
#[test]
fn sensitive_content_representation_controls_and_duplicate_codings()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    for (media, body) in [
        ("text/plain; charset=\"UTF-8\"", "ordinary"),
        ("application/json; charset=utf-8", "{\"value\":42}"),
        (
            "application/x-www-form-urlencoded",
            "flag&message=ordinary+content",
        ),
    ] {
        req.headers = vec![
            tinysecurity_bus::EgressHeader {
                name: "Content-Type".into(),
                value: media.into(),
            },
            tinysecurity_bus::EgressHeader {
                name: "Content-Encoding".into(),
                value: "Identity".into(),
            },
        ];
        req.payload = body.into();
        assert_eq!(scope.check(&req, 1, &dns).denial, None);
    }
    for headers in [
        vec![
            ("Content-Encoding", "identity"),
            ("content-encoding", "identity"),
        ],
        vec![("Content-Type", "text/plain; charset=utf-8; charset=utf-8")],
        vec![("Content-Type", "text/plain; boundary=x")],
        vec![("Content-Type", "text/plain; broken")],
    ] {
        req.headers = headers
            .into_iter()
            .map(|(name, value)| tinysecurity_bus::EgressHeader {
                name: name.into(),
                value: value.into(),
            })
            .collect();
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    Ok(())
}

#[test]
fn every_address_floor_class_denies_all_mixed_dns_orders()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    for forbidden in [
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.0",
        "100.127.255.255",
        "224.0.0.1",
        "240.0.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2002:a00:1::1",
        "2001:0:808:808:0:0:f5ff:fffe",
        "2001:db8::1",
        "2001:2::1",
        "100::1",
        "100:0:0:1::1",
        "3fff::1",
        "5f00::1",
        "fec0::1",
    ] {
        for answers in [
            vec!["8.8.8.8", forbidden],
            vec![forbidden, "2606:4700:4700::1111"],
        ] {
            let dns = Dns {
                calls: AtomicUsize::new(0),
                answers: answers
                    .into_iter()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()?,
            };
            assert_eq!(
                scope.check(&request(id.clone()), 1, &dns).denial,
                Some(EgressDenial::Address),
                "{forbidden}"
            );
        }
    }
    Ok(())
}

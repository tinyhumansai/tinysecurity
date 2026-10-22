//! Immutable owner-bound egress registration. Registry locks never span DNS work.
use crate::{
    EgressClock, Resolver, privacy,
    resolver::MonotonicClock,
    url_guard::{self, Endpoint},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tinysecurity_bus::{
    BrowserDialAuthorization, BrowserDialRequest, BrowserDialResponse, ConsumeBrowserDialRequest,
    DataCategory, EgressDenial, EgressPolicy, EgressPolicyId, EgressTransport, Error, PrivacyMode,
    RedactorConfig, Result, ScopedEgressRequest, ScopedEgressResponse, SubjectScope,
    TransportAuthorization, ValidateBrowserDialRequest,
};
use tinysecurity_redact::Redactor;
/// Immutable registered policy; scope IDs themselves do not authenticate a caller.
#[derive(Debug)]
pub struct RegisteredEgressPolicy {
    policy: EgressPolicy,
    id: EgressPolicyId,
    clock: Arc<dyn EgressClock>,
    redactor: Redactor,
    state: Mutex<LeaseState>,
    active_generation: Arc<AtomicU64>,
}
#[derive(Debug, Default)]
struct LeaseState {
    last: u64,
    generation: u64,
    faulted: bool,
    issued: Vec<TransportAuthorization>,
    browser_dials: Vec<BrowserDialAuthorization>,
    live_browser_dials: Vec<BrowserDialAuthorization>,
}
impl RegisteredEgressPolicy {
    /// Resolve and authorize one browser socket destination without asserting
    /// an HTTP method, headers, or plaintext payload the proxy cannot observe.
    #[must_use]
    pub fn authorize_browser_dial(
        &self,
        request: &BrowserDialRequest,
        generation: u64,
        resolver: &dyn Resolver,
    ) -> BrowserDialResponse {
        let result = self.prepare_browser_dial(request, generation, resolver);
        match result {
            Ok(authorization) => BrowserDialResponse {
                generation,
                denial: None,
                authorization: Some(authorization),
            },
            Err(denial) => BrowserDialResponse {
                generation,
                denial: Some(denial),
                authorization: None,
            },
        }
    }

    /// Build a bounded, session-bound grant after checking every destination address.
    fn prepare_browser_dial(
        &self,
        request: &BrowserDialRequest,
        generation: u64,
        resolver: &dyn Resolver,
    ) -> std::result::Result<BrowserDialAuthorization, EgressDenial> {
        let started = self.now()?;
        let (endpoint, sockets) = self.browser_dial_target(request, generation, resolver)?;
        let deadline = started.saturating_add(u64::from(self.policy.validity_ms));
        if self.now()? >= deadline {
            return Err(EgressDenial::Stale);
        }
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| EgressDenial::Stale)?;
        let authorization = BrowserDialAuthorization {
            authorization_id: hex(&bytes),
            session_id: request.session_id.clone(),
            scheme: endpoint.url.scheme().to_owned(),
            hostname: endpoint.hostname,
            port: endpoint.port,
            addresses: sockets,
            subject: self.policy.owner.clone(),
            policy_id: self.id.clone(),
            generation,
            expires_at_ms: deadline,
        };
        self.retain_browser_dial(authorization, generation)
    }

    /// Validate the browser request and resolve its complete approved socket set.
    fn browser_dial_target(
        &self,
        request: &BrowserDialRequest,
        generation: u64,
        resolver: &dyn Resolver,
    ) -> std::result::Result<(Endpoint, Vec<std::net::SocketAddr>), EgressDenial> {
        if request.expected_generation != generation {
            return Err(EgressDenial::Stale);
        }
        if request.session_id.is_empty() || request.session_id.len() > 128 {
            return Err(EgressDenial::Stale);
        }
        self.observe_generation(generation)?;
        if request.policy_id != self.id || request.policy_id.0.len() > 64 {
            return Err(EgressDenial::Scope);
        }
        if request.scheme != "http" && request.scheme != "https" {
            return Err(EgressDenial::Url);
        }
        if request.port == 0
            || request.hostname.is_empty()
            || request.hostname.len() > 253
            || request
                .hostname
                .contains(['/', '?', '#', '@', '%', '\\', '[', ']'])
            || request.hostname.chars().any(char::is_control)
        {
            return Err(EgressDenial::Url);
        }
        // TLS contents are opaque at a CONNECT proxy. Require an explicit host
        // classification and refuse the class under Sensitive or LocalOnly.
        if self.policy.privacy != PrivacyMode::Standard
            || !self
                .policy
                .data_categories
                .contains(&DataCategory::OpaqueBrowserTraffic)
        {
            return Err(EgressDenial::Privacy);
        }
        let authority = if request.hostname.contains(':') {
            format!("[{}]", request.hostname)
        } else {
            request.hostname.clone()
        };
        let endpoint = url_guard::parse(&format!(
            "{}://{}:{}/",
            request.scheme, authority, request.port
        ))?;
        if endpoint.hostname != request.hostname
            || endpoint.port != request.port
            || endpoint.url.scheme() != request.scheme
        {
            return Err(EgressDenial::Url);
        }
        if endpoint.ip.is_some_and(url_guard::forbidden) {
            return Err(EgressDenial::Address);
        }
        if !self.destination_registered(&endpoint) {
            return Err(EgressDenial::Destination);
        }
        let addresses = match endpoint.ip {
            Some(ip) => vec![ip],
            None => resolver
                .resolve(&endpoint.hostname, Duration::from_secs(2), 64)
                .map_err(|_| EgressDenial::Resolver)?,
        };
        if addresses.is_empty() || addresses.len() > 64 {
            return Err(EgressDenial::Resolver);
        }
        if addresses.iter().copied().any(url_guard::forbidden) {
            return Err(EgressDenial::Address);
        }
        let mut sockets: Vec<_> = addresses
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, endpoint.port))
            .collect();
        sockets.sort_unstable();
        sockets.dedup();
        Ok((endpoint, sockets))
    }

    /// Retain a grant only while its policy generation is active and capacity remains.
    fn retain_browser_dial(
        &self,
        authorization: BrowserDialAuthorization,
        generation: u64,
    ) -> std::result::Result<BrowserDialAuthorization, EgressDenial> {
        let now = self.now()?;
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        if state.faulted
            || state.generation != generation
            || self.active_generation.load(Ordering::Acquire) != generation
        {
            return Err(EgressDenial::Stale);
        }
        if authorization.expires_at_ms <= now {
            return Err(EgressDenial::Stale);
        }
        state
            .browser_dials
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        state
            .live_browser_dials
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        if state.browser_dials.len() + state.live_browser_dials.len() >= 256 {
            return Err(EgressDenial::Stale);
        }
        state.browser_dials.push(authorization.clone());
        Ok(authorization)
    }

    /// Consume one exact browser grant for one of its approved sockets.
    #[must_use]
    pub fn consume_browser_dial(
        &self,
        request: &ConsumeBrowserDialRequest,
        generation: u64,
    ) -> bool {
        let authorization = &request.authorization;
        let dial = &request.request;
        if self.active_generation.load(Ordering::Acquire) != generation
            || authorization.policy_id != self.id
            || authorization.subject != self.policy.owner
            || dial.policy_id != self.id
            || dial.policy_id.0.len() > 64
            || dial.expected_generation != generation
            || dial.session_id.is_empty()
            || authorization.session_id != dial.session_id
            || authorization.generation != generation
            || authorization.scheme != dial.scheme
            || authorization.hostname != dial.hostname
            || authorization.port != dial.port
            || !authorization.addresses.contains(&request.address)
            || request.address.port() != dial.port
        {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = self.clock.now_ms();
        if state.faulted
            || state.generation != generation
            || self.active_generation.load(Ordering::Acquire) != generation
            || now < state.last
        {
            if now < state.last {
                state.faulted = true;
            }
            return false;
        }
        state.last = now;
        state
            .browser_dials
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        state
            .live_browser_dials
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        if now >= authorization.expires_at_ms || state.live_browser_dials.len() >= 256 {
            return false;
        }
        let Some(index) = state
            .browser_dials
            .iter()
            .position(|issued| issued == authorization)
        else {
            return false;
        };
        state.browser_dials.swap_remove(index);
        state.live_browser_dials.push(authorization.clone());
        true
    }

    /// Validate an already consumed long-lived browser connection. This is a
    /// lease, not a dial permit: the caller must close the stream on false.
    #[must_use]
    pub fn validate_browser_dial(
        &self,
        request: &ValidateBrowserDialRequest,
        generation: u64,
    ) -> bool {
        let auth = &request.authorization;
        if self.active_generation.load(Ordering::Acquire) != generation
            || auth.policy_id != self.id
            || auth.subject != self.policy.owner
            || auth.generation != generation
        {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = self.clock.now_ms();
        if state.faulted
            || state.generation != generation
            || self.active_generation.load(Ordering::Acquire) != generation
            || now < state.last
        {
            if now < state.last {
                state.faulted = true;
            }
            return false;
        }
        state.last = now;
        state
            .live_browser_dials
            .retain(|lease| lease.expires_at_ms > now && lease.generation == generation);
        state.live_browser_dials.contains(auth)
    }

    /// Check original outgoing data before DNS. The authenticated private host
    /// adapter must derive subject, ceiling, classification and capability.
    /// The returned contract must be consumed by the actual transport owner.
    #[must_use]
    pub fn check(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
    ) -> ScopedEgressResponse {
        self.check_with_redactor(request, generation, resolver, &self.redactor)
    }
    /// Generic agent URL guard never opens a registered local host capability.
    #[must_use]
    pub fn url_guard(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> ScopedEgressResponse {
        if request.local_capability.is_some() {
            return ScopedEgressResponse {
                generation,
                denial: Some(EgressDenial::Address),
                authorization: None,
                cacheable: false,
            };
        }
        self.check_with_redactor(request, generation, resolver, redactor)
    }
    /// Native adapter supplies the active SDK credential registry for original-payload inspection.
    #[must_use]
    pub fn check_with_redactor(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> ScopedEgressResponse {
        match self.authorize(request, generation, resolver, redactor) {
            Ok(authorization) => ScopedEgressResponse {
                generation,
                denial: None,
                authorization: Some(authorization),
                cacheable: false,
            },
            Err(denial) => ScopedEgressResponse {
                generation,
                denial: Some(denial),
                authorization: None,
                cacheable: false,
            },
        }
    }
    fn authorize(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> std::result::Result<TransportAuthorization, EgressDenial> {
        let started = self.now()?;
        self.observe_generation(generation)?;
        if !self.matches_scope(request) {
            return Err(EgressDenial::Scope);
        }
        if !self.transport_allowed(request) {
            return Err(EgressDenial::Transport);
        }
        privacy::check(&self.policy, request, redactor).map_err(|_| EgressDenial::Privacy)?;
        let endpoint = url_guard::parse(&request.url)?;
        let addresses = if let Some(index) = request.local_capability {
            let capability = self
                .policy
                .local_capabilities
                .get(index as usize)
                .ok_or(EgressDenial::Privacy)?;
            let origin = url_guard::parse(&capability.origin)?;
            if !same_origin(&origin, &endpoint)
                || endpoint.url.path() != capability.path
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || request.category != capability.category
                || request.category != DataCategory::HostMetadata
            {
                return Err(EgressDenial::Privacy);
            }
            vec![
                endpoint
                    .ip
                    .filter(std::net::IpAddr::is_loopback)
                    .ok_or(EgressDenial::Address)?,
            ]
        } else {
            if endpoint.ip.is_some_and(url_guard::forbidden) {
                return Err(EgressDenial::Address);
            }
            if !self.destination_registered(&endpoint) {
                return Err(EgressDenial::Destination);
            }
            let addresses = match endpoint.ip {
                Some(ip) => vec![ip],
                None => resolver
                    .resolve(&endpoint.hostname, Duration::from_secs(2), 64)
                    .map_err(|_| EgressDenial::Resolver)?,
            };
            if addresses.is_empty() || addresses.len() > 64 {
                return Err(EgressDenial::Resolver);
            }
            if addresses.iter().copied().any(url_guard::forbidden) {
                return Err(EgressDenial::Address);
            }
            addresses
        };
        let mut sockets: Vec<_> = addresses
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, endpoint.port))
            .collect();
        sockets.sort_unstable();
        sockets.dedup();
        let deadline = started.saturating_add(u64::from(self.policy.validity_ms));
        let now = self.now()?;
        if now >= deadline {
            return Err(EgressDenial::Stale);
        }
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| EgressDenial::Stale)?;
        let authorization = TransportAuthorization {
            authorization_id: hex(&bytes),
            fingerprint: fingerprint(request).map_err(|_| EgressDenial::Privacy)?,
            url: endpoint.url.to_string(),
            hostname: endpoint.hostname,
            port: endpoint.port,
            addresses: sockets,
            subject: self.policy.owner.clone(),
            policy_id: self.id.clone(),
            generation,
            expires_at_ms: deadline,
        };
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        if state.faulted
            || state.generation != generation
            || self.active_generation.load(Ordering::Acquire) != generation
        {
            return Err(EgressDenial::Stale);
        }
        state
            .issued
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        if state.issued.len() >= 256 {
            return Err(EgressDenial::Stale);
        }
        state.issued.push(authorization.clone());
        Ok(authorization)
    }
    /// Check owner, immutable scope, current module generation and deadline before
    /// consuming a previously returned authorization. Does not authorize a new call.
    #[must_use]
    pub fn valid(
        &self,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        let Ok(now) = self.now() else {
            return false;
        };
        self.active_generation.load(Ordering::Acquire) == generation
            && authorization.policy_id == self.id
            && authorization.subject == self.policy.owner
            && subject == &self.policy.owner
            && authorization.generation == generation
            && now < authorization.expires_at_ms
            && self.state.lock().is_ok_and(|state| {
                state.generation == generation && state.issued.contains(authorization)
            })
    }
    /// Validate the exact outgoing original operation before consuming its grant.
    #[must_use]
    pub fn consume_request(
        &self,
        request: &ScopedEgressRequest,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        privacy::bounds(request).is_ok()
            && request.subject == *subject
            && request.policy_id == self.id
            && self.valid(authorization, subject, generation)
            && fingerprint(request).is_ok_and(|value| value == authorization.fingerprint)
            && self.consume(authorization, subject, generation)
    }
    /// Consume an exact live grant once. The executor must still enforce its deadline,
    /// sockets, Host/SNI, TLS verification and no redirects/proxy/fallback requirements.
    #[must_use]
    pub fn consume(
        &self,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        if !self.valid(authorization, subject, generation) {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = self.clock.now_ms();
        if state.faulted
            || state.generation != generation
            || self.active_generation.load(Ordering::Acquire) != generation
            || now < state.last
            || now >= authorization.expires_at_ms
        {
            if now < state.last {
                state.faulted = true;
            }
            return false;
        }
        state.last = now;
        let Some(index) = state
            .issued
            .iter()
            .position(|issued| issued == authorization)
        else {
            return false;
        };
        state.issued.swap_remove(index);
        true
    }
    /// Pinned direct always; Browser/Proxy only as an opted-in preflight, never for local capabilities.
    fn transport_allowed(&self, request: &ScopedEgressRequest) -> bool {
        request.transport == EgressTransport::PinnedDirect
            || (request.local_capability.is_none()
                && self
                    .policy
                    .preflight_transports
                    .contains(&request.transport))
    }
    /// Open public mode registers every destination; the address floor still decides afterwards.
    fn destination_registered(&self, endpoint: &Endpoint) -> bool {
        self.policy.open_public
            || self
                .policy
                .destinations
                .iter()
                .any(|rule| url_guard::matches(rule, endpoint))
    }
    fn matches_scope(&self, request: &ScopedEgressRequest) -> bool {
        request.policy_id == self.id
            && request.subject == self.policy.owner
            && request.tier == self.policy.ceiling
    }
    fn observe_generation(&self, generation: u64) -> std::result::Result<(), EgressDenial> {
        let active = self
            .active_generation
            .fetch_max(generation, Ordering::AcqRel);
        if generation < active {
            return Err(EgressDenial::Stale);
        }
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        if state.faulted
            || generation < state.generation
            || self.active_generation.load(Ordering::Acquire) != generation
        {
            return Err(EgressDenial::Stale);
        }
        if generation > state.generation {
            state.generation = generation;
            state.issued.clear();
            state.browser_dials.clear();
            state.live_browser_dials.clear();
        }
        Ok(())
    }
    fn now(&self) -> std::result::Result<u64, EgressDenial> {
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        let now = self.clock.now_ms();
        if state.faulted || now < state.last {
            state.faulted = true;
            return Err(EgressDenial::Stale);
        }
        state.last = now;
        Ok(now)
    }
}
fn fingerprint(request: &ScopedEgressRequest) -> Result<String> {
    privacy::bounds(request)?;
    let serialized = serde_json::to_vec(request).map_err(|_| Error::InvalidArguments)?;
    Ok(hex(&Sha256::digest(serialized)))
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
fn same_origin(a: &Endpoint, b: &Endpoint) -> bool {
    a.url.scheme() == b.url.scheme() && a.hostname == b.hostname && a.port == b.port
}
/// Bounded immutable policy registry, preserved across SDK reinitialization.
/// Register only on the private host configuration channel; no JSON value is authentication.
#[derive(Debug)]
pub struct EgressPolicyRegistry {
    scopes: Vec<(EgressPolicyId, Arc<RegisteredEgressPolicy>)>,
    clock: Arc<dyn EgressClock>,
    active_generation: Arc<AtomicU64>,
}
impl Default for EgressPolicyRegistry {
    fn default() -> Self {
        Self::with_clock(Arc::new(MonotonicClock(Instant::now())))
    }
}
impl EgressPolicyRegistry {
    /// Inject deterministic monotonic time.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn EgressClock>) -> Self {
        Self {
            scopes: vec![],
            clock,
            active_generation: Arc::new(AtomicU64::new(0)),
        }
    }
    /// Advance the shared generation atomically with host activation, invalidating
    /// old leases and preventing late old-generation DNS calls from issuing grants.
    /// Faulted scopes retain their own latch without preventing other scopes' reload.
    /// # Errors
    /// Refuse generation rollback.
    pub fn advance_generation(&self, generation: u64) -> Result<()> {
        if self
            .active_generation
            .fetch_max(generation, Ordering::AcqRel)
            > generation
        {
            return Err(Error::Faulted);
        }
        Ok(())
    }
    /// Register an immutable host-verified policy. Invalid candidates never change
    /// another subject's settings or invalidate previously accepted scopes.
    /// # Errors
    /// Reject malformed settings, bounds, forbidden grants or entropy failure.
    pub fn register(&mut self, mut policy: EgressPolicy) -> Result<EgressPolicyId> {
        if self.scopes.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        if [
            &policy.owner.user,
            &policy.owner.workspace,
            &policy.owner.agent,
        ]
        .iter()
        .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
            || !(1..=30_000).contains(&policy.validity_ms)
            || policy.destinations.len() > 128
            || policy.local_capabilities.len() > 16
            || policy.data_categories.len() > 6
            || policy.data_categories.contains(&DataCategory::Unknown)
        {
            return Err(Error::InvalidArguments);
        }
        if policy.preflight_transports.len() > 2
            || policy
                .preflight_transports
                .iter()
                .enumerate()
                .any(|(index, transport)| {
                    !matches!(transport, EgressTransport::Browser | EgressTransport::Proxy)
                        || policy.preflight_transports[..index].contains(transport)
                })
            || (policy.open_public
                && (!policy.destinations.is_empty() || !policy.local_capabilities.is_empty()))
            || (policy.open_public && policy.privacy == PrivacyMode::LocalOnly)
        {
            return Err(Error::InvalidArguments);
        }
        policy.destinations = policy
            .destinations
            .iter()
            .map(url_guard::normalize_rule)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::InvalidArguments)?;
        for capability in &policy.local_capabilities {
            let endpoint =
                url_guard::parse(&capability.origin).map_err(|_| Error::InvalidArguments)?;
            if endpoint.ip.is_none_or(|ip| !ip.is_loopback())
                || endpoint.url.path() != "/"
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || capability.category != DataCategory::HostMetadata
                || !capability.path.starts_with('/')
                || capability.path.len() > 2048
                || capability.path.contains(['?', '#', '\\'])
                || capability.path.chars().any(char::is_control)
            {
                return Err(Error::InvalidArguments);
            }
        }
        let redactor = Redactor::new(&RedactorConfig::default())?;
        for _ in 0..4 {
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
            let id = EgressPolicyId(hex(&bytes));
            if self.scopes.iter().any(|(old, _)| old == &id) {
                continue;
            }
            self.scopes.push((
                id.clone(),
                Arc::new(RegisteredEgressPolicy {
                    policy,
                    id: id.clone(),
                    clock: Arc::clone(&self.clock),
                    redactor,
                    state: Mutex::default(),
                    active_generation: Arc::clone(&self.active_generation),
                }),
            ));
            return Ok(id);
        }
        Err(Error::Unavailable)
    }
    /// Clone immutable policy; drop registry locks before URL parsing/DNS work.
    /// # Errors
    /// Reject unknown identifiers with no diagnostic content.
    pub fn get_owned(&self, id: &EgressPolicyId) -> Result<Arc<RegisteredEgressPolicy>> {
        self.scopes
            .iter()
            .find(|(old, _)| old == id)
            .map(|(_, scope)| Arc::clone(scope))
            .ok_or(Error::InvalidArguments)
    }
}
#[cfg(test)]
#[path = "guard_corpus_tests.rs"]
mod guard_corpus_tests;
#[cfg(test)]
#[path = "open_public_tests.rs"]
mod open_public_tests;
#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;

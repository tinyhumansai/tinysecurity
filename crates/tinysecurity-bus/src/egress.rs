//! Versioned scoped destination and privacy contracts.
use crate::{CallerContext, Decision};
use serde::{Deserialize, Serialize};
/// Host-registered privacy policy. Invocation fields never set authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Only an explicit host-local service capability may be reached; every
    /// other destination is refused before DNS.
    LocalOnly,
    /// Registered destination and declared data category are required; the
    /// address floor still applies to every resolved candidate.
    Standard,
    /// Standard, and additionally: credential and identifier categories, an
    /// unknown classification, and any original payload, URL (raw and percent
    /// decoded) or header that the shared redactor would change are refused,
    /// as are credential-bearing header names and unsupported body encodings.
    Sensitive,
}
/// Legacy `EgressCheckRequest` wire shape; unscoped calls cannot authorize effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressCheckRequest {
    /// Verified origin.
    pub caller: CallerContext,
    /// Configured privacy policy.
    pub privacy: PrivacyMode,
    /// Outgoing data categories.
    pub descriptor: DataDescriptor,
    /// Destination URL.
    pub destination: String,
}
/// Legacy `EgressCheckResponse` wire shape; unscoped calls cannot authorize effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressCheckResponse {
    /// Permission over the supplied data and destination.
    pub decision: Decision,
}
/// Legacy `UrlGuardRequest` wire shape; unscoped calls cannot authorize effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlGuardRequest {
    /// URL to resolve.
    pub url: String,
    /// Previous hop for redirect checks.
    pub redirect_from: Option<String>,
}
/// Legacy `UrlGuardResponse` wire shape; unscoped calls cannot authorize effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlGuardResponse {
    /// Authorization result.
    pub decision: Decision,
    /// TLS verification hostname.
    pub hostname: String,
    /// Addresses the transport MUST pin; this response alone is not rebinding protection.
    pub approved_addresses: Vec<String>,
}
/// Legacy `DataDescriptor` wire shape; unscoped calls cannot authorize effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataDescriptor {
    /// Whether credentials are present.
    pub contains_credentials: bool,
    /// Whether personal identifiers are present.
    pub contains_personal_data: bool,
    /// Whether data must stay local.
    pub local_only: bool,
}
/// Authenticated identity supplied only by the private trusted host adapter.
/// This wire value is not authentication; public/model callers cannot register it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectScope {
    /// Verified user identity.
    pub user: String,
    /// Verified workspace identity.
    pub workspace: String,
    /// Verified agent identity.
    pub agent: String,
}
/// Opaque immutable scoped policy reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicyId(pub String);
/// Trusted host classification of the actual original outgoing payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// Independently host-constructed content-free metadata.
    HostMetadata,
    /// User content without known credentials or identifiers.
    UserContent,
    /// Raw credentials.
    Credentials,
    /// Personal identifiers.
    Identifiers,
    /// Missing or unsupported assessment; always denied.
    Unknown,
    /// Browser HTTPS contents are opaque to the enforcing proxy. This category
    /// authorizes destination-only checks under Standard privacy; Sensitive
    /// privacy always refuses it because the content cannot be inspected.
    OpaqueBrowserTraffic,
}
/// Destination-only request made by the browser's enforced network proxy.
/// It deliberately carries no HTTP method, headers, body, or identity claim.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDialRequest {
    /// Immutable policy reference supplied by the private host configuration.
    pub policy_id: EgressPolicyId,
    /// Policy generation captured by the private host configuration. Stale
    /// browser sessions must not silently adopt a newer policy generation.
    pub expected_generation: u64,
    /// Unpredictable ID of the private browser proxy session. It binds grants
    /// and live leases to one proxy session and is never supplied by a page.
    pub session_id: String,
    /// `http` or `https`, as parsed from the actual proxy request.
    pub scheme: String,
    /// Canonical DNS hostname or IP literal from the actual proxy request.
    pub hostname: String,
    /// Effective destination port from the actual proxy request.
    pub port: u16,
}
impl std::fmt::Debug for BrowserDialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserDialRequest([REDACTED])")
    }
}
/// One-use browser socket grant; contains no HTTP payload or request fingerprint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDialAuthorization {
    /// Opaque random nonce recorded by `TinySecurity` until consumed.
    pub authorization_id: String,
    /// Browser proxy session that requested this exact destination.
    pub session_id: String,
    /// Canonical scheme and hostname bound to the vetted socket set.
    pub scheme: String,
    /// Canonical hostname retained for HTTP authority and TLS SNI.
    pub hostname: String,
    /// Effective destination port.
    pub port: u16,
    /// Every vetted candidate; the executor must dial one of these exact sockets.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Immutable owner binding.
    pub subject: SubjectScope,
    /// Immutable policy binding.
    pub policy_id: EgressPolicyId,
    /// Active security module generation.
    pub generation: u64,
    /// Monotonic module-clock deadline.
    pub expires_at_ms: u64,
}
impl std::fmt::Debug for BrowserDialAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserDialAuthorization([REDACTED])")
    }
}
/// Result of one destination-only browser authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDialResponse {
    /// Active security module generation, including denial.
    pub generation: u64,
    /// Stable refusal reason; absent only with an authorization.
    pub denial: Option<EgressDenial>,
    /// One-use authorization to dial the listed sockets.
    pub authorization: Option<BrowserDialAuthorization>,
}
/// Consume a browser socket grant before opening the exact selected socket.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeBrowserDialRequest {
    /// Exact destination checked by `TinySecurity`.
    pub request: BrowserDialRequest,
    /// Exact socket address selected from the grant's address set.
    pub address: std::net::SocketAddr,
    /// Exact one-use authorization returned for this destination.
    pub authorization: BrowserDialAuthorization,
}
/// Validate a live browser tunnel lease. Called periodically while a CONNECT
/// or WebSocket connection remains open; generation changes and expiry close it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateBrowserDialRequest {
    /// The authorization consumed immediately before the socket dial.
    pub authorization: BrowserDialAuthorization,
}
impl std::fmt::Debug for ValidateBrowserDialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValidateBrowserDialRequest([REDACTED])")
    }
}
impl std::fmt::Debug for ConsumeBrowserDialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsumeBrowserDialRequest([REDACTED])")
    }
}
/// Transport's verified enforcement ability. Ambient or model assertions do not qualify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressTransport {
    /// Direct TCP with exact approved IPs, original Host/SNI, verified TLS and no redirects/proxy.
    PinnedDirect,
    /// Browser currently has no verified per-hop enforcement contract.
    Browser,
    /// Proxy currently has no verified target-address enforcement contract.
    Proxy,
    /// Unspecified or unsupported executor.
    Unsupported,
}
/// Exact canonical endpoint or explicit subdomain rule, registered only by the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRule {
    /// HTTP or HTTPS only.
    pub scheme: String,
    /// Canonicalized DNS hostname or public IP literal; no wildcards.
    pub hostname: String,
    /// Concrete effective port.
    pub port: u16,
    /// Include descendants, never suffix lookalikes. IP rules cannot use this.
    pub include_subdomains: bool,
}
/// Narrow explicitly configured local service capability; never a generic agent URL exemption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEgressCapability {
    /// Exact HTTP(S) loopback IP origin; LAN, DNS names and metadata are rejected.
    pub origin: String,
    /// Exact path; arbitrary paths and redirects receive no capability.
    pub path: String,
    /// Only independently constructed host metadata is supported here.
    pub category: DataCategory,
}
/// Immutable private host configuration. No invocation can widen it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// Authenticated owner from host dispatch, not model arguments.
    pub owner: SubjectScope,
    /// Host-verified access ceiling; only the same tier can consume this scope.
    pub ceiling: crate::AccessTier,
    /// Privacy policy; independent of autonomy settings.
    pub privacy: PrivacyMode,
    /// Empty means no external destinations. Every URL still passes the unconditional floor.
    pub destinations: Vec<DestinationRule>,
    /// Supported original-payload classifications.
    pub data_categories: Vec<DataCategory>,
    /// Explicit narrow local host operations; inaccessible to generic agent URL guards.
    pub local_capabilities: Vec<LocalEgressCapability>,
    /// Bounded validity in milliseconds, between 1 and 30000.
    pub validity_ms: u32,
    /// Open public-internet mode (contract 1.15): any `http`/`https` destination
    /// is registered, so `destinations` must be empty. The unconditional address
    /// floor still applies to the literal and to every resolved candidate, so
    /// loopback, private, link-local, metadata, CGNAT and reserved addresses stay
    /// refused. Privacy mode and data-category checks are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open_public: bool,
    /// Transports other than [`EgressTransport::PinnedDirect`] this policy accepts
    /// for a preflight verdict (contract 1.15): only `Browser` and `Proxy`. The
    /// module cannot verify those executors pin the returned sockets, so the
    /// authorization is a best-effort verdict and DNS rebinding after it is the
    /// executor's risk. Local capabilities never use them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preflight_transports: Vec<EgressTransport>,
}
/// Scoped URL request, version 1.4. Registration and invocation require a confidential host bus.
/// Debug deliberately suppresses all payload, destination and identity values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEgressRequest {
    /// Immutable policy reference.
    pub policy_id: EgressPolicyId,
    /// Actual authenticated subject supplied by the adapter.
    pub subject: SubjectScope,
    /// Verified access tier.
    pub tier: crate::AccessTier,
    /// Exact original URL, preserved by the transport.
    pub url: String,
    /// Actual uppercase HTTP method; CONNECT and unsupported methods are refused.
    pub method: String,
    /// Independently host-derived original-payload classification.
    pub category: DataCategory,
    /// Original payload for independent secret/identifier checking; never diagnostic output.
    pub payload: String,
    /// Complete actual outgoing headers, including host-injected credentials; never model assertions.
    pub headers: Vec<EgressHeader>,
    /// Verified actual transport capability.
    pub transport: EgressTransport,
    /// Optional exact registered local capability index, host-only.
    pub local_capability: Option<u32>,
    /// Transformation evidence is unsupported until the approval engine exists; always rejected.
    pub transformation: Option<String>,
}
impl std::fmt::Debug for ScopedEgressRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedEgressRequest([REDACTED])")
    }
}
/// Stable content-free refusal reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressDenial {
    /// Scope or access ceiling mismatch.
    Scope,
    /// Missing, invalid or ambiguous URL.
    Url,
    /// Unconditional address floor.
    Address,
    /// Empty, failed, timed-out or oversized DNS result.
    Resolver,
    /// Unregistered destination.
    Destination,
    /// Privacy, original data or unsupported transformation.
    Privacy,
    /// Unsupported transport enforcement.
    Transport,
    /// Expired or stale generation authorization.
    Stale,
}
/// One-request noncacheable transport authorization. A URL decision alone is not
/// rebinding protection: the executor MUST pin these exact sockets without system
/// DNS fallback, ambient proxy, automatic redirects, cross-scope pooled reuse or
/// IP substitution in the URL. Preserve Host, SNI and hostname certificate checks.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportAuthorization {
    /// SHA-256 of the complete original scoped operation (including payload and actual headers).
    /// The executor MUST compare it to the exact operation it sends.
    pub fingerprint: String,
    /// Opaque one-call nonce; recorded by the module to prevent forged or replayed grants.
    pub authorization_id: String,
    /// Exact original URL parsed by the module.
    pub url: String,
    /// Canonical TLS verification and HTTP authority hostname.
    pub hostname: String,
    /// Effective port, including nondefault ports.
    pub port: u16,
    /// Exact vetted socket addresses; all candidates were checked.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Registered owner binding.
    pub subject: SubjectScope,
    /// Immutable policy binding.
    pub policy_id: EgressPolicyId,
    /// Effective module generation.
    pub generation: u64,
    /// Monotonic module-clock deadline; validate with the module before delayed send/retry.
    pub expires_at_ms: u64,
}
/// Noncacheable scoped decision; denial never returns destination/payload diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEgressResponse {
    /// Effective module generation, including denials.
    pub generation: u64,
    /// Stable denial; absent only when authorization is present.
    pub denial: Option<EgressDenial>,
    /// Typed pinned-transport requirements; not evidence that an executor consumed them.
    pub authorization: Option<TransportAuthorization>,
    /// Always false: DNS and privacy checks are never reusable across independent requests.
    pub cacheable: bool,
}

impl std::fmt::Debug for TransportAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportAuthorization([REDACTED])")
    }
}
/// Consume one exact issued authorization before transport execution. Replays deny.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeEgressAuthorizationRequest {
    /// Complete original operation the executor will send; changes invalidate the grant.
    pub request: ScopedEgressRequest,
    /// Authenticated actual subject, supplied only by the private host adapter.
    pub subject: SubjectScope,
    /// Exact previously issued authorization, without any address/destination changes.
    pub authorization: TransportAuthorization,
}

/// Actual outgoing header supplied by the trusted transport adapter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressHeader {
    /// HTTP token name; Host/authority and routing overrides are refused.
    pub name: String,
    /// Original value, including credentials; never diagnostic output.
    pub value: String,
}
impl std::fmt::Debug for EgressHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EgressHeader([REDACTED])")
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;

impl std::fmt::Debug for ConsumeEgressAuthorizationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsumeEgressAuthorizationRequest([REDACTED])")
    }
}

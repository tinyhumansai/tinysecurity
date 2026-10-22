# Browser destination authorization (contract 1.28)

`AuthorizeBrowserDial`, `ConsumeBrowserDial`, and `ValidateBrowserDial` extend scoped egress for a
browser proxy that cannot inspect TLS contents. The request contains the
host-authenticated policy id, expected policy generation, private browser
session id, and canonical destination scheme, hostname and effective port. The
session id binds grants and live leases to one private proxy session; it is
never supplied by a page. The request contains no subject or tier claim, HTTP
method, header, body, or claim about plaintext content. The only accepted
classification is `opaque_browser_traffic`, which the host must explicitly
register. Sensitive and local-only privacy modes refuse it because the proxy
cannot inspect or prove that the encrypted request contains no sensitive data.

Authorization applies the registered destination rules and the unconditional
address floor, resolves every DNS answer, and returns the exact vetted
`SocketAddr` set bound to the owner, policy, active generation, browser session,
and a bounded monotonic deadline. The browser proxy must consume a grant once
for one member of that socket set immediately before `connect`, then dial that
exact socket without another DNS lookup or ambient proxy. A redirect or new
subresource connection requires a new authorization. DNS grants are never reused.

This contract authorizes destination reachability only. It does not claim to
inspect browser payloads, to authorize an HTTP method, or to enforce the
executor. TinyComputer owns proxy enforcement and must refuse unsupported
browser transports before launch. Existing `Browser` and `Proxy` values in
`preflight_transports` retain their best-effort semantics for the legacy
`ScopedEgressRequest`; they do not authorize this socket contract.

The deadline bounds both socket admission and encrypted tunnel lifetime. After
consuming a grant, the transport periodically calls `ValidateBrowserDial` while
CONNECT or WebSocket traffic remains open. TinySecurity returns false when the
lease expires or the active policy generation changes. A false result or a bus
failure requires closing both sides of the stream. The registered validity is
at most 30 seconds; the lease is not renewed.

Generation changes invalidate outstanding grants. Resolver faults, empty or
oversized answer sets, private or otherwise non-global candidates, expired
grants, stale generations, mismatched scope or destination, and replayed
consumption all deny. The host must call this member only through its private
authenticated adapter; JSON identity fields never authenticate themselves.

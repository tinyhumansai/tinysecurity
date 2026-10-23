# Runtime secret-scope registration (contract 1.29)

`RegisterSecretScope2` lets a trusted host adapter add a secret resolver after
the module has initialized. This supports tenant and embedded-agent approval
scopes without reinitializing the process-global secret registry.

The host must register the corresponding approval scope first. The request
carries only the immutable `SecretRegistration2` descriptor and its approval
scope ID. The module resolves the live scope from its approval engine and
derives the native subject, durable subject, policy reference, and generation
from that canonical scope. A caller cannot supply or override those fields.

Registration is bounded by the native registry's 65,536 lifetime scope
identities. An exact repeat is idempotent and preserves the existing resolver,
including its persistent failure state. Reusing a registration ID with a
different descriptor is denied. Revoked runtime IDs stay tombstoned for the
life of the native registry and cannot be reactivated by registering the same
descriptor again; a replacement needs a new ID. Native admission checks the
expected approval generation while holding the registry lock, so an in-flight
generation change cannot add stale authority.

Retiring or replacing an approval scope first revokes native secret handles,
drops pending secret grants and aliases, and removes its runtime secret
registrations. Re-registering requires a live approval scope and an immutable
secret descriptor. Initialized secret registrations remain configured but
their old handles are invalidated by the same retirement boundary.

The new member is host-only, uses the authenticated module connection, and
returns only the opaque registration ID and active status. It does not return
subjects, backend contents, keys, or plaintext. Older modules do not implement
this member and therefore do not satisfy contract 1.29.

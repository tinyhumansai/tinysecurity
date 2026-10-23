# Host skill-scan decisions (contract 1.29)

**Status:** Accepted; implementation is under review in TinySecurity PR #48.
**Owner:** TinySecurity bus contract and policy engine.
**Plan:** [implementation plan](../plans/skill-scan-contract-1.29.md).

## Problem

OpenHuman's TinySkills scanner has `Pass`, `Warn`, and `Block` outcomes, but
the security policy bus cannot represent those outcomes before a skill runs.
Without a typed check, a warning cannot enter the standard approval resolver
and a block cannot be distinguished from ordinary tool permission.

## Goals and non-goals

- Let an authenticated host submit its scan verdict to the policy engine.
- Require human approval for warnings and make blocks non-overridable.
- Bind the result to the exact installed bundle using a digest.
- Keep TinySkills parsing and scanning in TinySkills; TinySecurity consumes only
  the host-computed verdict.
- Do not let models or remote callers assert scan results.

## Proposed behavior

`Check::SkillScan` carries the trusted host's `Pass`, `Warn`, or `Block` result
for the exact installed skill bundle an agent is about to execute. The request
also carries a lowercase SHA-256 digest over the document and every resource
the run can expose. TinySecurity binds that digest into the approval request;
it does not read skill files or trust a verdict supplied by a model or caller.
This check is supplemental: the host must include the normal host-effect check
in the same call, and a scan result alone never authorizes a tool.

The host must derive the verdict from its scanner over the same bytes the run
will consume. It must preserve that snapshot for the run, or verify the digest
again before exposing any resource. A changed bundle requires a fresh scan and
policy evaluation. The digest is an approval binding, not a content signature
or a substitute for the host's authenticated bus adapter.

Policy maps the verdicts as follows:

- `Pass` succeeds this check; all other policy checks still apply.
- `Warn` returns `ApprovalUnavailable`, which the host maps to its existing
  human-approval path. It is human-only: auto-approve-all, a whole-tool or flow
  grant, a previous approval, and the judge cannot bypass this fresh decision.
- `Block` returns `DenialReason::Content`, a hard refusal that approval cannot
  override.
- A malformed digest returns `DenialReason::InvalidContext`.

The check is not reusable by registered-policy decision caching. Its verdict
and bundle digest remain in the canonical call fingerprint and approval
binding, so a changed document cannot reuse the earlier warning decision.

Contract 1.29 is additive for older same-major hosts. Such hosts retain the
1.28 behavior and do not gain skill-scan enforcement until their host adapter
sends this check. OpenHuman pins an exact module artifact in its registry, so
the host adapter and a module artifact that supports 1.29 must ship together.

## Acceptance criteria

- The wire type round-trips all verdicts and requires a bundle digest.
- `Pass` allows this check, `Warn` produces the existing approval requirement,
  and `Block` produces `DenialReason::Content`.
- Malformed digests deny with `DenialReason::InvalidContext`.
- A warning enters the persisted human-approval lifecycle; a block cannot be
  converted into a pending approval by policy evaluation.
- Auto-approve-all, grants, and judge decisions cannot bypass a warning's
  fresh human decision.
- A 1.29 host rejects a 1.28 module, and accepts later 1.x module minors.

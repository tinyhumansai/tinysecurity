# Host skill-scan decisions (contract 1.29) implementation plan

Specification: [host skill-scan decisions](../specs/skill-scan-contract-1.29.md).

Status: implementation is under review in TinySecurity PR #48. OpenHuman host
integration remains tracked in OpenHuman #7328 and must wait for the released
1.29 module artifact.

## Goal and boundaries

Add an authenticated host-supplied skill-scan verdict to policy evaluation and
bind it to the exact skill bundle digest. TinySecurity consumes the host's
verdict; TinySkills continues to own bundle parsing and scanning. The check
never authorizes a tool by itself, and older 1.x hosts retain their prior
behavior until they send the new check.

## Ordered work

1. **Define the wire contract.** Add the verdict and digest fields to
   `crates/tinysecurity-bus/src/policy.rs` and export them from
   `crates/tinysecurity-bus/src/lib.rs`. First pin verdict round trips,
   malformed digests, and additive 1.x compatibility in
   `crates/tinysecurity-bus/src/policy_tests.rs`,
   `crates/tinysecurity-bus/tests/scoped_wire.rs`, and
   `crates/tinysecurity-bus/tests/wire.rs`.
2. **Evaluate policy.** Implement `Pass`, `Warn`, and `Block` precedence in
   `crates/tinysecurity-policy/src/scoped.rs` and `engine.rs`. Add failing
   tests in `crates/tinysecurity-policy/src/engine_tests.rs` for hard block,
   human-only warning, malformed context, and cache exclusion before changing
   the evaluator.
3. **Bind human approval.** Include the verdict and bundle digest in approval
   identity and prevent auto-approval, grants, prior decisions, or judge
   results from satisfying a warning in
   `crates/tinysecurity-approval/src/binding.rs` and `engine.rs`. Pin the
   lifecycle and scope behavior in `engine_scopes_tests.rs` first.
4. **Wire the native module.** Dispatch the check through
   `crates/tinysecurity-module/src/adapter.rs`. Add adapter regressions in
   `adapter_host_tool_tests.rs`, and verify module-owned approval/callback
   behavior through `adapter_secret_tests.rs` and
   `adapter_secret_cipher_fixture_tests.rs` before completing the dispatch.
5. **Document compatibility and verify.** Keep `MODULE.md`, `README.md`,
   `docs/README.md`, and this specification aligned. Update this plan's
   checklist as the module tests and hosted platform matrix complete.

## Verification

Run from the TinySecurity repository root:

```sh
cargo fmt --all -- --check
cargo test -p tinysecurity-bus skill_scan_has_stable_verdict_wire_forms
cargo test -p tinysecurity-bus contract_bump_is_additive_for_older_hosts_and_modules
cargo test -p tinysecurity-policy host_skill_scan
cargo test -p tinysecurity-approval skill_scan_warning_enters_human_approval
cargo test -p tinysecurity-module evaluate_applies_host_skill_scan_verdicts_before_run_workflow
scripts/ci-cancel-aware.sh cargo test --quiet -p tinysecurity-bus -p tinysecurity-policy -p tinysecurity-approval
scripts/ci-cancel-aware.sh cargo clippy -p tinysecurity-bus -p tinysecurity-policy -p tinysecurity-approval -p tinysecurity-module --all-targets --all-features -- -D warnings
```

The required module CI also covers Linux, macOS, Windows, release latency,
coverage, and the native module fixture. Record these as complete only after
the exact PR head passes each required job.

## Completion checklist

- [x] Additive bus contract and wire compatibility tests.
- [x] Policy precedence and non-cacheable scan binding.
- [x] Human-only warning approval and hard-block behavior.
- [x] Native module dispatch and adapter coverage.
- [x] Specification and module documentation updated.
- [ ] Review thread resolved and exact-head CI green.
- [ ] Merge and publish the 1.29 module artifact before OpenHuman adopts it.

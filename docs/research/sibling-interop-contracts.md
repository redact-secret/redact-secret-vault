# Sibling interoperability contract inventory

Observed 2026-10-08 for [#166](https://github.com/redact-secret/redact-secret-vault/issues/166), [#169](https://github.com/redact-secret/redact-secret-vault/issues/169), and [#171](https://github.com/redact-secret/redact-secret-vault/issues/171).
Contract revision: `vault-interop-v1`.
Status: pinned public Rust API inspection; production native authority compatibility is not qualified. Execution evidence belongs to the [qualification record](qualification-vault-interop-v1.md).

## Pinned sources

The repositories were inspected through GitHub's authenticated contents/tree API without cloning. Links pin complete commit revisions, not moving branch heads.

- anonymizer: `e6864ee05248b8c83d1e7484e84e8b1cde27ed67`. [Cargo.toml](https://github.com/redact-secret/anonymizer/blob/e6864ee05248b8c83d1e7484e84e8b1cde27ed67/Cargo.toml), [public exports](https://github.com/redact-secret/anonymizer/blob/e6864ee05248b8c83d1e7484e84e8b1cde27ed67/src/lib.rs), [capture trait and orchestration](https://github.com/redact-secret/anonymizer/blob/e6864ee05248b8c83d1e7484e84e8b1cde27ed67/src/reversible.rs), [README and status](https://github.com/redact-secret/anonymizer/blob/e6864ee05248b8c83d1e7484e84e8b1cde27ed67/README.md).
- restore: `e9c4863bf887956d004438d0229d04a9a85667dc`. [Cargo.toml](https://github.com/redact-secret/restore/blob/e9c4863bf887956d004438d0229d04a9a85667dc/Cargo.toml), [public exports](https://github.com/redact-secret/restore/blob/e9c4863bf887956d004438d0229d04a9a85667dc/src/lib.rs), [authority trait](https://github.com/redact-secret/restore/blob/e9c4863bf887956d004438d0229d04a9a85667dc/src/authority.rs), [request context](https://github.com/redact-secret/restore/blob/e9c4863bf887956d004438d0229d04a9a85667dc/src/request.rs), [authority semantics](https://github.com/redact-secret/restore/blob/e9c4863bf887956d004438d0229d04a9a85667dc/docs/authority-semantics.md).

The [native distribution ADR](../decisions/native-rust-interop-boundary.md) is the common decision. The [language-neutral specification](../specs/vault-interop.md) is the compatibility target, not an assertion that sibling developmental APIs implement every requirement.

## Anonymizer capture surface

Crate `anonymizer` version `0.1.0`, edition 2021, declared Rust floor `1.98.1`, `publish = false`, no dependencies. `default = []`; feature `reversible` exposes `anonymize_reversible`, `Capture`, `CaptureLimits`, `TokenSink`.

```rust
pub trait TokenSink {
    type Error;
    fn begin(&mut self) -> Result<(), Self::Error>;
    fn stage(&mut self, captures: &[Capture<'_>], limits: CaptureLimits)
        -> Result<Vec<String>, Self::Error>;
    fn commit(&mut self) -> Result<(), Self::Error>;
    fn abort(&mut self) -> Result<(), Self::Error>;
}
```

`Capture::value()` borrows the accepted original UTF-8 slice. `accepted()` supplies accepted-span metadata, not a retention grant. Stage returns exactly one unique token in capture order, each `<rsv_[a-z2-7]{26}>`, exactly 32 ASCII bytes. Defaults allow 100,000 captures and 32 token bytes; compatibility qualification must use lower host limits where required. The engine validates output bounds before committing and returns output only after commit. Failed begin, stage, token validation or commit attempts abort; abort failure becomes `CleanupFailed`. Capture Debug excludes values; sink errors are discarded rather than formatted. The host must provide trusted authorization context, retention eligibility and unpredictable tokens.

This is a synchronous transactional contract. The implemented `captureOccurrences` JavaScript profile accepts finalized UTF-8 byte spans in one atomic batch. It does not expose a public native Rust transaction; the qualification bridge owns private isolated staging until publication. A production adapter cannot bypass documented APIs, stage mappings through private internals, or claim idempotent compensating cleanup without evidence. Process-loss/cancellation cleanup is a separate host responsibility. Zero-copy capture does not imply no retained plaintext: the injected authority owns mapping lifetime.

## Restore authority surface

Package `redact-secret-restore` version `0.1.0`, library import `redact_secret_restore`, edition 2021, declared Rust floor `1.85`, `publish = false`, no dependencies, empty default features.

```rust
pub trait RestoreAuthority {
    type Grant;
    fn preflight(&self, plan: &RestorePlan<'_>) -> Result<Self::Grant, RestoreError>;
    fn consume(&mut self, grant: Self::Grant, plan: &RestorePlan<'_>)
        -> Result<ResolvedValues, RestoreError>;
}
```

The public entry is `restore(&RestoreRequest<'_>, &mut authority, Limits)`. Request context contains trusted tenant, principal, session, sink and purpose; capture references and fields provide source scope and structural paths. Validation does not authenticate those identifiers. `RestorePlan` owns no original values and binds occurrences to field identity and UTF-8 byte ranges. The authority must bind the preparation grant to the exact plan and authority instance, recheck current policy/expiry/revocation/budgets at atomic consumption, and return one owned value per occurrence through `ResolvedValues::new(Vec<String>)` only after definite commit.

Duplicates cost one use per occurrence; with one remaining use, two occurrences deny the whole batch. This matches the sibling's stated inspection of Vault, but qualification must verify each selected Vault execution profile independently. `NotCommitted`, `Committed`, and `Indeterminate` outcomes matter: unknown commit releases no values, and reconstruction failure after successful consume may burn uses. Values are owned copies and dropped after reconstruction; no erasure guarantee follows. There is no async/cooperative cancellation contract or general mapping enumeration API.

The implemented JavaScript `createRestoreAuthority` adapter now exposes opaque request-bound preflight and exact ordered complete-value consume over both the in-memory and persistent server public APIs. The pinned Rust siblings still have no direct native adapter; qualification exercises this asynchronous JavaScript surface through a test bridge. A bridge can hand complete values to the native restore trait after definite authorized consumption; it does not qualify a native in-process Vault or permit arbitrary token lookup. Persistent receipt behavior and policy races must remain explicit.

## Native execution recipe

Fetch only the two pinned source archives into a temporary directory if execution is required; no full history or long-lived worktrees are needed. Verify archive contents and Cargo manifests before running. Use a toolchain meeting anonymizer's `1.98.1` floor, share a temporary `CARGO_TARGET_DIR`, set `CARGO_BUILD_JOBS=1` on limited disks, and remove sources/targets after qualification. Dependency declarations are local path dependencies to those extracted repositories; enable anonymizer's `reversible` feature. Tests should call the exported APIs above with synthetic findings and an explicit qualification-only authority, then compare safe outcomes with Vault's public API harness.

Useful upstream baseline checks, from each respective source directory:

```sh
cargo test --locked --no-default-features --features reversible  # anonymizer
cargo test --locked --no-default-features                       # restore
```

Those upstream tests alone do not qualify Vault interoperability. The qualification record must distinguish native sibling execution with a test authority, public Vault execution through a development bridge, and any actual production authority adapter. Record exact toolchain/revisions, positive and negative cases, failure/commit behavior, and bounded safe diagnostics. Never include plaintext fixture values in reports or callback error text.

## Compatibility gates

1. Both traits are bulk and synchronous; persistent Vault is asynchronous. Any blocking/async/transport adapter requires an explicit supported profile and cancellation/commit-uncertainty evidence.
2. Capture consumes externally accepted ranges; the implemented JavaScript `captureOccurrences` accepts those ranges without rescanning, while ordinary `capture` continues to select ranges through core integration. Retention eligibility and block handling cannot be inferred solely from sibling findings.
3. Restore's value handoff differs from Vault's structured output API. A final-output comparison tests semantic parity, not a native value-resolution endpoint.
4. Strict malformed-marker rejection, Unicode offset conversion, duplicate occurrence budgets, exact paths and committed output failures must be tested as profile semantics, not erased by API translation.
5. No production native Vault adapter, official Rust Vault contracts crate, qualified FFI, or qualified IPC path was found in the inspected public surfaces. This inventory does not claim absence in uninspected private branches.

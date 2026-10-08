# Native Rust interoperability distribution boundary

Scope: workspace.

Status: Accepted 2026-10-08 for the design boundary, not native production support.
Issue: [#169](https://github.com/redact-secret/redact-secret-vault/issues/169), parent [#166](https://github.com/redact-secret/redact-secret-vault/issues/166).
Contract revision: `vault-interop-v1`.

## Decision and scope

Vault owns a language-neutral interoperability specification and conformance vectors. Native consumers own thin adapters to their public Rust traits, `anonymizer::TokenSink` and `redact_secret_restore::RestoreAuthority`. A repository boundary does not require a runtime boundary: native composition uses borrowed input/ranges, bounded bulk operations, and in-process calls when the application supplies a qualified native authority. Neither JSON, Node.js, a subprocess nor a service is mandatory.

This decision supplies a shared compatibility target. It does not supply a Rust Vault implementation or make the existing TypeScript implementation callable natively. At the pinned sibling revisions in the [compatibility inventory](../research/sibling-interop-contracts.md), neither sibling has a qualified production Vault adapter. Consumer-owned adapters translate contracts, not authorization semantics. An application authority remains separately qualified; an adapter must not invent a second retention, policy, cryptographic, or transaction authority to fill a missing API.

The [interop specification](../specs/vault-interop.md) is normative for revision `vault-interop-v1`. Existing server authorization and persistent store specifications continue to own their respective security behavior. Native adapters must carry trusted tenant, principal, session, source/capture, sink, purpose and structural-path context; reject missing context; bind capture and restore transactions; and preserve current expiry, revocation, eligibility and usage checks. Syntax or a visible type label grants no authority. Profile-specific stricter parsing is recorded explicitly rather than silently called equivalent.

## Evaluated alternatives

Each option is evaluated against ownership, API stability, dependency size, plaintext lifetime, serialization/copy cost, portability, WASM/server implications, release cadence, conformance burden, semantic drift, and second-authority risk.

### 1. Language-neutral specification with consumer-owned trait adapters, selected

Vault owns normative semantics and vectors; siblings own traits and adapters; the host owns authentication and injected authority. Contract revisions remain stable independently of developmental trait signatures. No shared runtime dependency is imposed. Borrowed capture slices avoid compulsory value copies, while restore's current `Vec<String>` handoff necessarily owns values until reconstruction/drop; Rust does not prove erasure. Native calls require no serialization and can be statically linked. Portability follows each consumer's tested toolchains, with WASM qualification separate and server persistence requiring real atomic authority evidence. Releases need not be lockstep: each adapter pins a contract revision and sibling revision. Every adapter must run shared cases and its native failure/race tests. Explicit profile mappings limit semantic drift. Adapters must stay thin; implementing authority/storage/crypto is a separate proposal and review.

### 2. Small official Rust contracts crate without storage or crypto, deferred

Vault would own Rust types, traits and versioned releases as well as the spec. A minimal standard-library-only crate could keep dependencies small and borrow capture data without serialization. It would not supply a working authority or bridge to TypeScript. Native/server composition could benefit from common types, but WASM and async choices would add compatibility obligations. A separate crate release cadence and MSRV policy would be required. Conformance remains necessary because common types do not enforce policy, atomicity or lifecycle. Central types reduce signature drift but can freeze the wrong consumer abstractions. Validators, clocks, issuance or policy conveniences could grow into a second authority; those must be excluded. Current sibling traits differ enough that a crate is premature. Reconsider only after two qualified adapters demonstrate a stable shared surface.

### 3. FFI around an existing implementation, not selected

Vault would own an ABI and the wrapped implementation; consumers would own safe wrappers. ABI/version and allocator ownership must remain stable. Binding/runtime dependencies can exceed a traits-only integration, especially when wrapping JavaScript. Plaintext ownership, copies, callback lifetimes and exception/panic boundaries need explicit auditing; zero-copy is not assumed. Platform and WASM support depend on the concrete runtime and ABI. Server use requires unchanged whole-request commit semantics. Runtime and wrapper releases must track compatible versions. FFI requires semantic conformance plus memory/ABI testing. Translation can drift in offsets, errors and cancellation. Wrapping an authority avoids cloning it, but a convenience fallback authority would not. No qualified ABI exists here, so no production path is approved.

### 4. Optional local service or IPC profile, separately qualified only

Vault owns service behavior; the application owns transport deployment, authentication and endpoint trust. A versioned protocol supplies API stability at the cost of serialization, buffers, transport dependencies and additional plaintext copies/lifetimes. Local IPC is platform-specific; network transport changes the threat model. Browser/WASM clients need a separately designed trust boundary; servers need authenticated principals and tenant binding independent of caller-provided claims. Client and service releases can negotiate compatible revisions. Protocol, transport, cancellation, commit uncertainty and leak testing add conformance work. Drift arises when transport errors obscure committed state. A single service may remain the authority, but per-client fallback storage would create a competing authority. No mandatory gateway or default process bridge is introduced.

### 5. Generated conformance vectors with independent implementations, selected as evidence only

Vault owns vector semantics and revisions; each implementation owns code and releases. Versioned vectors have negligible production dependency cost and impose no runtime serialization. Test runners may serialize synthetic data, but production plaintext lifetime and copy cost remain implementation-specific. Vectors are portable across native, WASM and server environments without qualifying any of them. Implementations can release independently against a pinned vector revision. Vectors reduce semantic drift but cannot establish memory safety, backend durability, identity authenticity or all races; runtime/profile evidence is still required. Generating expected results from the implementation under test is insufficient. Independent authority implementations would create additional security implementations, so this decision authorizes independent adapters and test models, not a Rust Vault clone.

## Path labels and qualification

- **Native contract:** supported design distribution is the spec plus consumer-owned Rust traits/adapters. This label describes the contract, not production runtime support.
- **Development/test bridges:** an explicitly invoked Node/public-API bridge or synthetic authority may test compatibility. It must be isolated from production packages, receive only synthetic fixtures in qualification, use bounded payloads and fixed safe diagnostics, and advertise that it is a bridge. Passing it does not qualify native integration.
- **Qualified production paths:** existing JavaScript/Python claims remain limited to their published qualification records. This ADR adds no qualified Rust, FFI, IPC, service, WASM or persistent profile. A future record must pin implementation and contract revisions, toolchains, transport if any, trust context, plaintext lifetime, budget semantics, cancellation/commit outcomes, race schedules and leak evidence.
- **Intentionally unsupported paths:** mandatory Node subprocess/JSON/network composition, raw token-to-value lookup or mapping export, a Rust database-backed Vault clone, authority derived from model text, and silently weakening failure/commit semantics to fit a synchronous trait.

## Consequences and open gates

Capture receives already finalized eligible ranges; it does not rescan or reimplement detector arbitration. The host must independently establish retention eligibility, including PII opt-in and block rejection. Restore performs bounded complete preflight followed by an authoritative consume; a preparation grant is not a reservation. Unknown commit releases no values, and committed consumption cannot be undone by reconstruction failure.

The inspected capture trait is synchronous and requires abort after any attempted begin, including partial commit cleanup. The implemented JavaScript batch profile `captureOccurrences` and asynchronous server `createRestoreAuthority` are concrete compatibility surfaces; the qualification bridge runs those public operations with isolated staging, not a native Rust Vault. The inspected restore trait is synchronous, charges per occurrence, and requires values only after definite consumption. An asynchronous persistent Vault cannot be described as a direct native adapter without reconciling those differences and qualifying the actual implementation. Cancellation and process-loss recovery remain host obligations. The [inventory](../research/sibling-interop-contracts.md) records concrete gaps rather than inventing a hidden blocking wrapper.

Both sibling repositories can reference this stable decision and `vault-interop-v1` without independently choosing a mandatory bridge. Official Rust packaging, async traits, FFI, IPC and native production qualification require separate tracked decisions and evidence.

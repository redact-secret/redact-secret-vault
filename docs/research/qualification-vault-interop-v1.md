# Vault sibling interoperability qualification, vault-interop-v1

Date: 2026-10-08. Scope: workspace, synthetic development reference qualification. This record does not publish a package or qualify a production Rust authority, IPC service, key-management system, or new database durability profile.

## Revisions and reproduction

- Vault base: `9e03618626e86fc3c790bbf4572a12f2adb8f8f6`, plus the unreleased #166 interoperability implementation in this change. The merge commit identifies its final revision; all tests are reproducible from that revision.
- anonymizer: `e6864ee05248b8c83d1e7484e84e8b1cde27ed67`, crate `anonymizer` 0.1.0, public `reversible` feature.
- restore: `e9c4863bf887956d004438d0229d04a9a85667dc`, crate `redact-secret-restore` 0.1.0.
- Contract: [vault-interop-v1](../specs/vault-interop.md). Shared vectors: [1.0.0, schema 1](../../conformance/interop/v1/README.md), SHA-256 in its committed manifest.
- Local runtime: Node.js 22.16.0, npm 11.4.1, Rust/Cargo 1.98.1, macOS arm64. Rust fixture is a debug build, not optimized engine benchmark evidence. Python 3.14.7 for the local shared token consumer; CI records its own runtime.

Run the exact commands in [qualification/interop/README.md](../../qualification/interop/README.md). Downloads/builds live in ignored `.qualification/interop/`; fixture code is tracked separately. There are no registry Rust dependencies or copied sibling implementations. The pipe calls each pinned engine's actual public trait, not a replacement engine.

## Executed reference profiles

The locally qualified development reference profile is one exclusive Node.js in-memory server authority and one Rust process, synthetic trusted host context, bounded whole-input capture, and structured-field restoration. The actual server principal resolver and current policy enforce tenant/principal, session, sink/path and purpose checks. Capture authorization remains trusted host responsibility, matching the existing server contract. The pipe transports synthetic source/values only, never a real credential.

A second local reference runs the actual persistent server, real record crypto and local key provider over the ciphertext-only **non-durable memory store**. It proves persistent orchestration and budget/receipt behavior, not persistence. The existing PostgreSQL CI job additionally executes `qualification/interop/postgres.test.mjs` over real serving-role transactions. Local runs without the two database URLs explicitly skip that test. PostgreSQL execution results must be read from that PR's CI check; no local PostgreSQL result is claimed here. Existing named PostgreSQL crash/failover profiles remain governed by their original qualification record.

## Evidence and boundaries

`reference.test.mjs` covers a credential, multiple credentials, repeated identical values with distinct tokens, Unicode byte boundaries, multiple fields, irreversible display output plus reversible spans, wrong sink/path/capture, tenant-policy denial, expiry/revoke, duplicate budget, revoke after preflight, capture failure, staged abort cleanup, postcommit malformed value handoff and replay denial, all shared token vectors in Rust, and persistent ciphertext-backed roundtrip. The caller/core makes irreversible decisions upstream; no detector or policy engine is copied into Rust fixtures.

Shared JS vector tests exercise all token forms and capture/authority scenario groups. The persistent fault consumer exercises create failure and both applied/unapplied indeterminate commit outcomes, attempt resolution, and no replay. Python consumes the same token vectors only; no Python bulk adapter claim is made. Native stage/abort/postcommit scenarios are mapped to real Rust tests in the shared manifest. API-specific negative tests additionally cover invalid UTF-8 spans, final blocked occurrence, whole-batch validation, explicit occurrence order, mutable request snapshots, opaque grant reuse/mutation, policy changes, racing preflights, and safe diagnostics.

The bridge never emits source-derived output before confirmed capture. During staging it retains one complete capture inside a private authority. Rust validates tokens and constructs output before commit confirmation. There is no external restore entry point during that interval. Abort revokes the entire unpublished batch; persistent abort also deletes ciphertext through authorized lifecycle calls. This adapter supplies bounded local observational atomicity, not durable distributed rollback. Process loss or failed cleanup requires reconciliation and no output; crash-resilient staged transactions and cancellation are not qualified.

## Allocation, copies and plaintext lifetime

The anonymizer borrows original UTF-8 slices; the pipe hex-encodes them and copies source through Rust strings, Node Buffers and JavaScript strings. Vault alone retains mappings and issues unpredictable tokens. The fixture checks occurrence IDs and exact byte-slice correspondence, and never stores a second token/value map.

Restore receives exact requested values only after whole-request consume. Values cross hex transport into Rust-owned `ResolvedValues` and reconstructed output. In-memory Vault privately constructs its own result before synchronous budget mutation, then hands off values after commit; the accepted [ordering decision](../decisions/adapt-bulk-restore-authority.md) makes that difference explicit. Persistent decrypted byte buffers are wiped by the existing crypto/server cleanup paths. JavaScript/Rust strings, transport buffers and output copies are dropped by the host; no deterministic string erasure or heap-retention bound was measured or promised. The local key provider is test infrastructure, not newly qualified production key management. No value, issued token or payload-bearing exception is logged by the reference protocol.

## Measured integration overhead

A minimum one-occurrence roundtrip, 25 sequential samples, synthetic `SYNTHETIC_MEASUREMENT`, debug Rust fixture, the local runtime above. CPU/IPC scheduling and first-use warmup affect these figures; they are descriptive development measurements, not a production regression gate.

- pipeControlRoundtrip: median `0.014833 ms`.
- syntheticHexEncodeDecode: median `0.000777 ms`.
- captureAuthority: median `0.042375 ms`.
- restorePreflight: median `0.031833 ms`.
- restoreConsume: median `0.035000 ms`.
- bridgeAndEnginesResidual: median `0.218418 ms`.
- totalRoundtrip: median `0.344708 ms`.
- Total measured bridge frame bytes: `30550`.

Capture, preflight and consume timers wrap actual JavaScript authority calls. The control pipe probe runs no engine or authority and uses a smaller frame. The hex probe measures encoding/decoding separately from IPC. The residual includes both Rust engines, host scheduling and all remaining pipe/serialization work; it cannot be interpreted as isolated engine or serialization latency. `measure.mjs` records its exact sample/runtime/profile metadata in `.qualification/reports/interop-v1.json`; CI produces its own artifact. No synthetic engine-only result is a Vault production performance claim.

## Support claims and remaining unsupported profiles

Contract specified, JavaScript reference APIs implemented, local reference tested, and shared cross-language token conformance passed are distinct claims. This change qualifies the reproducible synthetic **development reference profile** above. Production support still requires a named native host adapter or transport/deployment threat model and its own qualification. No native Rust Vault, FFI ABI, production IPC/network bridge, WASM authority, Worker bulk capture, distributed staged cleanup, cross-process cancellation, universal leak prevention or additional storage/key-provider profile is claimed.

Both pinned sibling contracts can target the same accepted contract revision and vector version. Existing sibling repository files remain unchanged; their maintainers can reference this record without inheriting a mandatory bridge or copying authority internals.

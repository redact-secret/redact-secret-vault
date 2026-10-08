# Adapt the bulk restore authority boundary

Scope: workspace

Status: accepted for `vault-interop-v1`, in-memory and persistent reference implementations. Persistent deployment qualification for the new two-stage path remains open. Scope: #168, compatible with restore#5 and restore#8.

## Decision

Provide a nonconsuming, no-plaintext whole-request preflight and an opaque, instance-bound, single-use grant. Consume reruns current authorization/lifecycle checks and hands off exactly the requested values in explicit occurrence order after whole-request budget consumption. Trusted application context, source membership, destination and purpose remain Vault-owned. The sibling engine owns parsing and reconstruction, not authorization or token storage.

Keep the in-memory core's private output construction before synchronous budget mutation. The old comment described the opposite order. There is no callback or asynchronous boundary between private construction and mutation, and nothing returns to the caller until consumption completes. Preserving this ordering avoids charging a request whose private construction fails. The new requested-value handoff follows commit; external reconstruction failure cannot refund it.

## Alternatives and consequences

Reconstructing values from restored strings is ambiguous and can corrupt values containing separators or token-like text, so expose only exact requested occurrence values. Per-token lookups and consume loops cannot preserve all-or-none budgets. Calling restore to simulate preflight would consume and release values. Grant reservation would require a new lifecycle model and is unnecessary; grants instead revalidate.

The in-memory server snapshots validated fields across asynchronous policy callbacks. The reference adapter preserves original destination paths and explicitly compensates for JavaScript field enumeration when returning portable plan order. Errors contain bounded fixed diagnostics and truthful commit knowledge. Unknown outcomes fail closed.

The persistent server implements the two-stage API by sharing its existing authorization/decryption preflight and rerunning it at consume before the existing #105 batch transaction. Preflight stops before string conversion and store commit and wipes private decrypted buffers. This preserves #109 ownership, transaction retry rules and receipt nonreplay. Its new two-stage path is tested with the non-durable memory store, not newly qualified for PostgreSQL deployments. Policy remains outside the transaction, with the existing revision fence and documented residual window.

Specification and tests: [bulk authority](../specs/interop-restore-v1.md), `packages/vault-server/test/interop-restore.test.mjs`.

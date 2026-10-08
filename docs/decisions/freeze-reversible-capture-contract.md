# Freeze the reversible bulk capture boundary

Scope: workspace.

Status: accepted 2026-10-08 for the contract and portable/in-memory/persistent JS batch implementations.
Scope: [issue 167](https://github.com/redact-secret/redact-secret-vault/issues/167),
part of [interop epic 166](https://github.com/redact-secret/redact-secret-vault/issues/166).

## Decision

Adopt [vault-interop-v1 capture](../specs/interop-capture-v1.md): trusted finalized
UTF-8 occurrences enter one bounded operation, Vault issues identities, and explicit
occurrence IDs leave in the committed receipt. No detection, raw mapping iteration,
plaintext export or token-derived authority crosses the transformation boundary.
`captureOccurrences` supplies portable, server, and persistent batch entry points
without changing their underlying authorization and lifecycle ownership.

## Consequences

Host finding eligibility is a trust boundary. Every submitted block rejects the
batch, but the portable Vault cannot authenticate an omitted upstream finding.
This public operation must never be exposed as an unauthenticated retention API.
PII retention still requires explicit exact types; detecting PII activation is
unnecessary on a no-detection boundary.

The Rust stage/commit model requires an exclusive private local bridge, and persistent async authority requires a separately qualified native adapter;
the existing scanning captures cannot silently stand in for them. A staged token
must be unusable before commit and failed abort requires reconciliation. Returning
tokenized text only after one definite batch commit protects the portable API.

## Rejected alternatives and open work

Per-slice captures plus revoke leave partial commits and change detector semantics.
Zipping independently scanned results can bind a token to the wrong occurrence.
Concatenating values loses source boundaries. Mapping export and transformer token
issuance duplicate authority. None is an allowed compatibility shortcut.

Native staged transport cancellation/ambiguous
commit reconciliation, and cross-runtime marker parity still require qualification.
Only independently recorded host profiles may claim Rust interoperability.
No new durable storage profile follows from accepting this ADR.

## Qualification adapter scope

The local Rust/JavaScript qualification bridge may stage one entire batch in an
exclusive private in-memory authority, then confirm commit after Rust validates
all tokens and constructs output. Staged identities never reach an external
consumer and no restore operation is possible before confirmation. Abort removes
the entire unpublished capture; local validation or cleanup failure returns no
source-derived output. This is a bounded qualification adaptation, not a generally
reusable shared or durable TokenSink transaction backend. Persistent adapters must
also delete staged ciphertext under lifecycle authorization; revocation alone is
not cleanup. The qualification record must identify the exact profiles tested.

# Reversible bulk capture, vault-interop-v1

Status: accepted contract; portable, in-memory server and persistent JavaScript
bulk operations implemented. Native Rust TokenSink support is limited to the
explicit profiles and evidence in the interop qualification record. This contract
alone does not qualify a transport or a new durable storage profile.

## Ownership and eligible input

The trusted host provides one complete UTF-8 source and an ordered list of finalized
accepted occurrences. Each occurrence has a unique bounded `occurrenceId`, exclusive
UTF-8 byte range `[start,end)`, safe finding `type`, and finalized `action`. Offsets
must be code point boundaries, increasing and non-overlapping. No normalization or
re-detection occurs. Identical values in different occurrences remain distinct.
`block` denies the entire operation. Only `redact` is retainable; `warn`/`allow`
are rejected by this profile. PII requires an exact-type retention allowlist.

The host is responsible for authenticating the source, applying the upstream
finalized finding policy, and submitting all relevant blocked findings before
selecting reversible spans. Occurrence claims cannot prove that an omitted block
never existed. The portable process profile trusts its caller, as existing
`createVault` does, and supplies no multi-tenant authentication. Treating untrusted
model findings as host authority is outside this contract.

Vault owns unpredictable token identity, the only token-to-value mapping, grants,
expiry, revocation, use budgets, and all restore decisions. Anonymizer may borrow
values while transforming its own input; it never maintains a second mapping or
writes values/tokens to its manifest or diagnostics. Safe metadata is limited to
bounded occurrence IDs, offsets, types, counts, outcome codes and opaque capture
IDs. Finding text, snippets and arbitrary metadata are excluded.

## Language-neutral operation

`captureBatch(trustedContext, source, occurrences, grants, maxUses?)` either returns
one committed receipt or a fixed safe error. The receipt contains `captureId`,
`expiresAt`, and one `{occurrenceId, token, type}` item for each submitted occurrence.
Correspondence comes from the occurrence identifier, never token spelling, sorting,
value deduplication or type labels. Tokens are unique within the batch, and use
Vault's profile: exactly 32 ASCII bytes, `<rsv_`, 26 lowercase base32 characters
(`a-z2-7`), `>`. Grammar is recognition, never authorization.

Authenticated server context resolves principal, tenant, source/session binding,
policy revision and the allowed capture operation. The transformer supplies no
credentials or authoritative tenant. Grants name an exact sink and field paths;
no wildcard fallback is permitted. Default `maxUses` is 1. Configured entry TTL
sets an absolute expiry at successful capture, bounded by the authority's lifetime;
restore also checks session/tenant and current policy. A capture ID is correlation,
not a release grant. A new unrelated capture cannot reuse a source session by
merely copying an identifier.

All limits and all claims are checked before issuance or retention. Implementations
must bound occurrence count before traversing or reserving the list, source bytes
before unbounded decoding, individual value bytes, total retained bytes, token
bytes, and output growth before output allocation. The effective bounds are the
minimum of transformer, authority, and storage limits. Token generation failure,
invalid final occurrence, PII rejection, or exhausted capacity denies the whole
batch and exposes no usable tokenized output. No plaintext appears in errors.

## Transaction form and failures

The equivalent staged form is `begin -> stage(all occurrences) -> commit`, with
`abort` valid after every begin attempt. `stage` returns exactly one token per
occurrence in submitted order for the current anonymizer TokenSink API; the host
binds that vector to explicit occurrence IDs. A staged token is unusable until
commit. No source-derived output leaves the transformer before definite commit.
Commit publishes the entire mapping atomically. Abort is idempotent and successful
abort removes every mapping from that attempted transaction, including partial
external writes; logical revoke alone is not successful physical cleanup.

Failed begin, stage, token validation, output construction or commit requires abort.
Failed abort/cancellation/process loss withholds output and requires host
reconciliation. A timeout or uncertain store acknowledgement is not a definite
commit; never expose output or blindly retry. Persistent implementations must
atomically create ciphertext records and commit durability under their separately
qualified storage profile before releasing the receipt. Reconciliation may fence
or delete partial records under lifecycle authorization, without exporting values.
Cleanup is not verified erasure from backups or managed-runtime copies.

## Mapping to current JavaScript surfaces

`vault.captureOccurrences(input, occurrences, {release, maxUses?, pii?})` implements
the portable single-process batch form without detection or mapping export. Its
receipt also contains the fully tokenized `text`; this is returned only after the
same synchronous mapping commit as `capture`. The complete validated plan precedes
any entry insertion. UTF-8 offsets are converted to exact JavaScript UTF-16 ranges
inside Vault. All correspondence items and receipt arrays are frozen.

Default authority bounds are 256 live entries, 64 KiB retained values, 8 KiB per
value, 1 MiB source/output, 1,024 submitted findings, 10 minute entry TTL, 60 minute
vault TTL, and maximum requested use count 16. These are configurable only within
`LIMIT_CEILINGS`; they are not anonymizer's defaults (100,000 captures).
The batch output cap is `maxInputBytes`, including token expansion. Caller-provided
PII findings do not activate the detector, because this operation never scans.

Existing `vault.capture` and `vault-server.capture` scan the whole input and return
only token/type items. They cannot supply occurrence correspondence by zipping a
separately produced finding list. In-memory server capture records tenant and
release-policy shadow entries; capture-time authentication is still host-owned.
Persistent server capture resolves principal/session, applies lifecycle policy,
encrypts and conditionally creates a whole capture before returning. Those are
useful authority implementations, and the in-memory server now exposes
`captureOccurrences(input, occurrences, {issuedTenant, release, maxUses?, pii?})`,
which retains its existing tenant, policy revision, grant, purpose, source and
restore-budget authority. Capture-time authentication remains host-owned, exactly
as for scanning server capture. Persistent server also exposes
`captureOccurrences(input, occurrences, {context, requestId?, release, maxUses?, pii?})`.
It reuses the same principal/session resolver, lifecycle gate, encryption, atomic
store create and ambiguous-outcome fencing as scanning capture, with occurrence IDs
added only to the returned receipt. The store sees no occurrence IDs or plaintext.
Native staged adapters must reuse these existing authority gates; direct access to a store or mapping is prohibited.

The current synchronous Rust `TokenSink` asks for tokens during stage, before
commit. The JavaScript batch call is not a drop-in implementation of that staged
trait: calling it in stage would make mappings usable prematurely. A native
transaction surface or qualified exclusive private host bridge is required. Do not simulate it by
calling capture per value and compensating with revoke, or concatenate slices and
re-scan. An async persistent call likewise cannot satisfy the synchronous trait
without an explicitly qualified host boundary. Unicode-Cf marker parity remains
part of native qualification, not a claim based on grammar matching alone.

## Evidence and compatibility anchor

The public surface adds a bounded operation rather than changing existing capture
semantics. `packages/vault/test/capture-occurrences.test.mjs` covers repeated values,
UTF-8 offsets, exact correspondence, real capture/restore, replay, partial block,
wrong boundaries, overlap, duplicate IDs, retention opt-in, limits and collisions.
All fixtures are synthetic. The server bulk tests include tenant/source/purpose checks, and persistent bulk tests
include session checks, ciphertext creation, no-write partial validation failure,
create failure and leak hygiene. Memory-backed persistent tests establish transaction
behavior, not crash/failover durability. Other authority denial cases remain governed by the
restore specification and its existing tests.

Upstream anchors: [anonymizer issue 7](https://github.com/redact-secret/anonymizer/issues/7),
[public TokenSink](https://github.com/redact-secret/anonymizer/blob/main/src/reversible.rs),
and [qualification status](https://github.com/redact-secret/anonymizer/blob/main/qualification/release-status.json).
These are foundation evidence, not proof that this new bridge is already qualified.

## Private local staged bridge

A host can implement the synchronous TokenSink by owning an exclusive in-memory
Vault instance and withholding every issued token, capture ID and restore entry
point until commit confirmation. Stage may populate the private Vault using one
batch call; commit publishes only after all transformer validation succeeds;
abort revokes the whole unpublished capture, physically removing its in-memory
mapping. In this profile no other code can restore a staged token before commit,
so externally observable behavior is atomic. The host must enforce exclusive
transaction access and idempotent abort; sharing the staged Vault or exposing its
restore API invalidates this equivalence. Revoking the portable mapping satisfies
cleanup, while persistent logical revocation alone does not. This profile is
local, synchronous and non-durable, never distributed transaction evidence.

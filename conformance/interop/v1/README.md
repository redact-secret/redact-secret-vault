# Vault interop vectors v1

Contract revision: `vault-interop-v1`. Schema version: `1`. Vector version: `1.0.0`.

The same [vectors.json](vectors.json) is consumed by Vault JavaScript, the shipped Python token parser, and pinned Rust sibling qualification. [schema.json](schema.json) describes the input and exact expected outcomes. [manifest.json](manifest.json) pins the SHA-256 of both byte-for-byte files and maps every lifecycle case to its execution profile. The cases contain unmistakably synthetic values and fixed synthetic token identities; no wrapping keys, data keys or customer data are present.

## Execute

Build the workspace first using the root interop qualification command. From the repository root, standalone consumers are:

```sh
node --test conformance/interop/v1/test.mjs conformance/interop/v1/persistent.test.mjs
python3 conformance/interop/v1/test.py
npm run qualify:interop
```

JavaScript's first runner validates the JSON schema and integrity, exercises the actual token parser and literal-capture gate, public finalized-occurrence capture, and the real server restore-authority adapter. The persistent runner invokes public `captureOccurrences` and `createRestoreAuthority` over the existing fault-injected volatile test store; it is contract evidence, not PostgreSQL/SQLite crash durability qualification. Python imports the shipped parser without installing extras and applies the same token cases. It does not qualify Python capture-occurrence adapters or Rust authority handoff, which are absent.

The Rust qualification runner uses the pinned anonymizer/restore public crates. Token scan results consume these JSON cases through the qualification bridge. Native reference tests cover transactional sink failure/abort and committed reconstruction failure where those synchronous native APIs are applicable. A reference authority is a test model; actual Vault bridge execution is recorded separately in the [qualification record](../../../docs/research/qualification-vault-interop-v1.md).

## Input and result semantics

`tokens` supplies exact input text and expected canonical occurrences in order, marker count, malformed-marker classification and literal-capture collision outcome. Bodies are fixed synthetic identities, never production-issued entropy samples. Case changes and Unicode Cf insertion are rejected as malformed; valid repeated occurrences stay separate for budgets. Python's broader Cf stripping is described in its parser documentation; these shared cases specify the common profile and do not claim exhaustive Unicode equivalence.

`scenarios` supplies a stable ID, group, operation, minimal synthetic inputs and explicit expected outcomes. `valuesReturned` counts values released by the operation under test. A capture receipt exposes tokens and safe metadata, never original values. `usesConsumed` counts the operation's additional use consumption; `null` means an indeterminate caller outcome, and is not zero. Fixture setup may already consume a use to establish an exhausted state. `entries` is the surviving committed mapping count after the tested capture operation. A denied complete request releases no values and does not consume unrelated uses. Race schedules execute both preflights before either consume, or order revoke/consume deterministically, without sleeps.

Wrong-principal, wrong-session and wrong-purpose cases use explicit host policy, because identifiers alone do not authenticate or authorize. Wrong-capture/source tests replace trusted capture references. Independent policy windows remain part of the authority profile. Postcommit output failure is exercised by the native restore engine with malformed complete-value handoff, which withholds output while leaving committed uses spent. Indeterminate persistent commit exercises both applied and unapplied faults and checks receipt reconciliation without plaintext replay or automatic retry.

## Applicability and coverage

- Token group: all 10 cases execute against JavaScript and Python parsers; the Rust runner executes the same input texts against its public scanner through `RestorePlan`.
- Capture group: repeated values, correspondence, source binding, grant paths and limits execute against public `captureOccurrences`; partial stage failure and abort cleanup execute against the pinned native `TokenSink`; unavailable persistent create executes against the persistent public capture API.
- Restore group: unknown/forged tokens, source/capture/tenant/principal/session/sink/path/purpose, expiry, revoke, exhausted/duplicate budgets, mixed denial, two-preflight race and both revoke orders execute against the real JavaScript authority. Native engine tests cover committed output failure. The persistent runner covers unknown commit in both applied and unapplied branches.

The manifest deliberately distinguishes production implementation behavior from test-model behavior. A sibling may state **qualified against Vault interop vectors 1.0.0, contract vault-interop-v1**, only with its pinned implementation/runtime and the applicable case IDs/profile named. Passing parser cases alone qualifies parser cases alone.

## Compatibility policy

Schema major version changes whenever a consumer must parse data differently. Vector major version changes whenever an existing expected outcome, token grammar, offset unit, authorization rule, budget accounting or commit interpretation changes; the contract revision must change with normative semantic changes. Adding a new independent case is a vector minor revision. Correcting prose or metadata without changing inputs/expected outcomes is a patch revision. Removing an existing case is a major revision.

Keep released major-version directories immutable. Publish new vectors under a new versioned directory when major semantics change; retain the previous vectors for older consumers. Before the first release, reviewed corrections can amend this candidate `v1` bundle, with hash changes visible in the PR. After release, any vector-byte change requires a version change and new hashes. Consumers fail on unknown schema/contract versions or mismatched hashes; they do not silently skip unknown operations. SHA-256 is integrity/reproducibility evidence, not an authentication signature.

The manifest and runners provide visible failures when implementation behavior drifts from fixed expectations. Expected outcomes are written from the normative contract, not generated from whichever implementation is running. Changes require reviewing the specification, vectors, hashes, native mappings and qualification record together.

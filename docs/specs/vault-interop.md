# Vault interoperability revision vault-interop-v1

Status: accepted contracts and implemented JavaScript reference surfaces on main, not a package release. Shared vector version: `1.0.0`.

- [Bulk reversible capture](interop-capture-v1.md): trusted finalized UTF-8 spans, explicit occurrence IDs, Vault-owned issuance and whole-batch commit.
- [Bulk restore authority](interop-restore-v1.md): nonconsuming preflight, opaque single-use grant, fresh whole-request consume and exact ordered values.
- [Native Rust distribution decision](../decisions/native-rust-interop-boundary.md): consumer-owned Rust trait implementations against this specification. No mandatory bridge and no native Rust Vault implementation.
- [Versioned conformance vectors](../../conformance/interop/v1/README.md), with executable consumers and integrity manifest.
- [Pinned sibling compatibility](../research/sibling-interop-contracts.md) and [reference qualification](../research/qualification-vault-interop-v1.md).

A repository boundary does not require a process boundary. The reference pipe exists only to qualify the actual Rust engines against the JavaScript authority. Tokens carry identity, never authorization. No unrestricted mapping lookup, iteration, or plaintext dump API is provided.

## Compatibility policy

`vault-interop-v1` fixes semantics, not TypeScript object layout or transport bytes. A changed token grammar, occurrence correspondence, grant binding, consume ordering, duplicate-use rule, or commit-state meaning requires a new contract revision and new conformance major version. Additive compatible evidence may advance the vector minor version; corrections require a patch plus a published digest. Never silently replace published vectors. Languages independently qualify named adapters and runtime/backend profiles; passing token grammar alone is not authority qualification.

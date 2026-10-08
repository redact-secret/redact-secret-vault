# Reproducible sibling reference qualification

This development-only private pipe runs the real pinned Rust anonymizer and restore crates against the real JavaScript Vault authority. It does not ship in an npm package and is not a production IPC protocol.

Prerequisites: Node.js 22, npm, Rust/Cargo 1.98.1 or later, `tar`, and HTTPS access to the two public sibling repositories. No credential or key-service access is required. All source data is unmistakably synthetic.

```sh
npm ci --ignore-scripts
npm run build
node qualification/interop/prepare.mjs
node --test conformance/interop/v1/test.mjs conformance/interop/v1/persistent.test.mjs
python3 conformance/interop/v1/test.py
node --test qualification/interop/reference.test.mjs
node qualification/interop/measure.mjs
```

`prepare.mjs` downloads exact sibling commit archives, creates only `.qualification/interop/`, and builds the dependency-free Rust fixture there. The fixture implements each engine's public traits; it copies no engine or Vault implementation. `Cargo.lock` pins the local package graph. `reference.test.mjs` uses actual source byte spans, a real bulk capture, a real preflight/consume grant, and Rust reconstruction. Inspect the [qualification record](../../docs/research/qualification-vault-interop-v1.md) before interpreting support or performance.

After validation, remove `.qualification/interop/` to release the downloaded sources, archives, and Rust build outputs. This is regenerable output; retain `.qualification/reports/interop-v1.json` if its measured evidence is needed.

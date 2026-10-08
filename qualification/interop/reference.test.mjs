import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { openReference } from "./reference.mjs";

const spans = (input, values) => {
  let cursor = 0;
  return values.map((value) => { const start = input.indexOf(value, cursor); cursor = start + value.length; return [Buffer.byteLength(input.slice(0, start)), Buffer.byteLength(input.slice(0, cursor))]; });
};
const sharedVectors = JSON.parse(readFileSync(new URL("../../conformance/interop/v1/vectors.json", import.meta.url)));
const scenario = (id) => sharedVectors.scenarios.find((item) => item.id === id);
const cases = [
  ["one credential", "prefix SYNTHETIC_CREDENTIAL_ONE suffix", ["SYNTHETIC_CREDENTIAL_ONE"]],
  ["multiple credentials", "SYNTHETIC_CREDENTIAL_ONE plus SYNTHETIC_CREDENTIAL_TWO", ["SYNTHETIC_CREDENTIAL_ONE", "SYNTHETIC_CREDENTIAL_TWO"]],
  ["repeated values with independent identity", "SYNTHETIC_REPEAT SYNTHETIC_REPEAT", ["SYNTHETIC_REPEAT", "SYNTHETIC_REPEAT"]],
  ["Unicode byte boundaries", "한글 😀 SYNTHETIC_UNICODE end", ["SYNTHETIC_UNICODE"]],
];
for (const [name, input, values] of cases) test(`native roundtrip: ${name}`, async () => {
  const rig = await openReference();
  try {
    const captured = await rig.anonymize(input, spans(input, values));
    assert.equal(captured.denied, undefined);
    assert.equal(new Set(captured.tokens.map((t) => t.token)).size, values.length);
    const restored = await rig.restore([captured.captureId], { body: `model: ${captured.text}` });
    assert.deepEqual(restored.fields, [`model: ${input}`]);
    assert.equal((await rig.restore([captured.captureId], { body: captured.text })).denied, true);
  } finally { await rig.close(); }
});
test("multi-field restore preserves field and occurrence order", async () => {
  const rig = await openReference({ maxUses: 2 });
  try {
    const captured = await rig.anonymize("SYNTHETIC_MULTI", [[0, 15]]);
    const restored = await rig.restore([captured.captureId], { subject: `s ${captured.text}`, body: `b ${captured.text}` });
    assert.deepEqual(restored.fields, ["s SYNTHETIC_MULTI", "b SYNTHETIC_MULTI"]);
  } finally { await rig.close(); }
});
for (const failure of ["wrong-path", "wrong-sink", "wrong-capture", "duplicate-budget", "revoke", "expiry", "policy-context", "preflight-race"]) test(`native whole-plan denial: ${failure}`, async () => {
  let now = 1000;
  const rig = await openReference({ clock: () => now });
  try {
    const captured = await rig.anonymize("SYNTHETIC_DENIAL", [[0, 16]]);
    const fields = { [failure === "wrong-path" ? "forbidden" : "body"]: failure === "duplicate-budget" ? `${captured.text} ${captured.text}` : captured.text };
    if (failure === "revoke") await rig.vault.revoke(captured.captureId);
    if (failure === "expiry") now = captured.expiresAt;
    const options = {};
    if (failure === "wrong-sink") options.context = ["synthetic-tenant", "synthetic-principal", "synthetic-session", "wrong-sink", "qualification"];
    if (failure === "policy-context") options.context = ["wrong-tenant", "synthetic-principal", "synthetic-session", "reply", "qualification"];
    if (failure === "preflight-race") options.afterPreflight = (vault) => vault.revoke(captured.captureId);
    const result = await rig.restore([failure === "wrong-capture" ? "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa" : captured.captureId], fields, options);
    assert.equal(result.denied, true);
    assert.equal(result.fields, undefined);
    if (failure === "preflight-race") assert.equal(result.commitState, "NotCommitted");
  } finally { await rig.close(); }
});
test("capture failure withholds output and mapping", async () => {
  const rig = await openReference({ failStage: true });
  try {
    const vector = scenario("capture.partial-failure");
    const input = vector.input.values.join(" ");
    assert.equal((await rig.anonymize(input, spans(input, vector.input.values))).denied, true);
    assert.equal((await rig.vault.stats()).entries, vector.expected.entries);
  }
  finally { await rig.close(); }
});
test("postcommit reconstruction failure burns uses", async () => {
  const rig = await openReference({ failOutput: true });
  try {
    const captured = await rig.anonymize("SYNTHETIC_OUTPUT", [[0, 16]]);
    const result = await rig.restore([captured.captureId], { body: captured.text });
    assert.equal(result.denied, true); assert.equal(result.commitState, "Committed");
    await assert.rejects(rig.vault.preflightRestore({ context: { tenant: "synthetic-tenant", principal: "synthetic-principal" }, sessionId: "synthetic-session", purpose: "qualification", sink: "reply", captures: [captured.captureId], fields: { body: captured.text } }));
  } finally { await rig.close(); }
});
test("mixed irreversible then reversible forward construction", async () => {
  // Caller/core chooses irreversible findings; both constructions use the real engine.
  const source = "SYNTHETIC_IRREVERSIBLE SYNTHETIC_MIXED";
  const rig = await openReference();
  try {
    const irreversible = await rig.irreversible(source, spans(source, ["SYNTHETIC_IRREVERSIBLE"]));
    assert.equal(irreversible.denied, undefined);
    assert.equal(irreversible.text.includes("SYNTHETIC_IRREVERSIBLE"), false);
    const captured = await rig.anonymize(irreversible.text, spans(irreversible.text, ["SYNTHETIC_MIXED"]));
    assert.deepEqual((await rig.restore([captured.captureId], { body: captured.text })).fields, [irreversible.text]);
  } finally { await rig.close(); }
});

test("Rust consumes shared token vectors v1.0.0", async () => {
  const vectors = JSON.parse(readFileSync(new URL("../../conformance/interop/v1/vectors.json", import.meta.url)));
  const rig = await openReference();
  try {
    for (const vector of vectors.tokens) {
      const result = await rig.scan(vector.text);
      assert.equal(result[0] === "denied", vector.expected.malformed, vector.id);
      if (!vector.expected.malformed) assert.equal(Number(result[2]), vector.expected.tokens.length, vector.id);
    }
  } finally { await rig.close(); }
});

test("staged capture abort physically removes unpublished mappings", async () => {
  const rig = await openReference({ failCommit: true });
  try {
    const vector = scenario("capture.abort-cleanup");
    const input = vector.input.values.join(" ");
    assert.equal((await rig.anonymize(input, spans(input, vector.input.values))).denied, true);
    assert.equal((await rig.vault.stats()).entries, vector.expected.entries);
  } finally { await rig.close(); }
});

test("persistent authority complete native roundtrip over ciphertext-only memory store", async () => {
  const rig = await openReference({ persistent: true });
  try {
    const input = "SYNTHETIC_PERSISTENT SYNTHETIC_PERSISTENT";
    const captured = await rig.anonymize(input, spans(input, ["SYNTHETIC_PERSISTENT", "SYNTHETIC_PERSISTENT"]));
    assert.equal(captured.denied, undefined);
    assert.deepEqual((await rig.restore([captured.captureId], { body: captured.text })).fields, [input]);
    assert.equal((await rig.restore([captured.captureId], { body: captured.text })).denied, true);
  } finally { await rig.close(); }
});

test("empty reversible plan passes through without capture", async () => {
  const rig = await openReference();
  try { assert.equal((await rig.anonymize("ordinary synthetic text", [])).text, "ordinary synthetic text"); assert.equal((await rig.vault.stats()).entries, 0); }
  finally { await rig.close(); }
});

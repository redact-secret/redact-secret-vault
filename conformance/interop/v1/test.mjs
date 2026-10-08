import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createVault } from "../../../packages/vault/dist/index.js";
import { TOKEN_PATTERN, MARKER_PATTERN, countMatches } from "../../../packages/vault/dist/token.js";
import { createRestoreAuthority } from "../../../packages/vault-server/dist/index.js";
import { openServer, captureOne, SECRET_A } from "../../../packages/vault-server/test/helpers.mjs";

const bytes = await readFile(new URL("vectors.json", import.meta.url));
const vectors = JSON.parse(bytes);
const manifest = JSON.parse(await readFile(new URL("manifest.json", import.meta.url)));
const schemaBytes = await readFile(new URL("schema.json", import.meta.url));
const schema = JSON.parse(schemaBytes);
function validate(value, rule, path = "vectors") {
  if (rule.const !== undefined) assert.ok(value === rule.const, `${path}: const`);
  if (rule.enum) assert.ok(rule.enum.includes(value), `${path}: enum`);
  if (rule.type) {
    const types = Array.isArray(rule.type) ? rule.type : [rule.type];
    const actual = value === null ? "null" : Array.isArray(value) ? "array" :
      Number.isInteger(value) ? "integer" : typeof value;
    assert.ok(types.includes(actual), `${path}: type`);
  }
  if (rule.pattern) {
    const patterns = new Map([
      ["^[1-9][0-9]*\\.[0-9]+\\.[0-9]+$", /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/],
      ["^<rsv_[a-z2-7]{26}>$", /^<rsv_[a-z2-7]{26}>$/],
    ]);
    const pattern = patterns.get(rule.pattern);
    assert.ok(pattern, `${path}: supported schema pattern`);
    assert.ok(pattern.test(value), `${path}: pattern`);
  }
  if (rule.minimum !== undefined && value !== null) assert.ok(value >= rule.minimum, `${path}: minimum`);
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined) assert.ok(value.length >= rule.minItems, `${path}: minItems`);
    if (rule.items) value.forEach((item, index) => validate(item, rule.items, `${path}[${index}]`));
  } else if (value !== null && typeof value === "object") {
    for (const key of rule.required ?? []) assert.ok(Object.hasOwn(value, key), `${path}: required ${key}`);
    for (const key of Object.keys(value)) {
      if (rule.properties?.[key]) validate(value[key], rule.properties[key], `${path}.${key}`);
      else if (rule.additionalProperties === false) assert.fail(`${path}: unknown property ${key}`);
    }
  }
}
const known = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>";
const safeEqual = (actual, expected, label) => assert.ok(actual === expected, label);
const denied = (error) => error.commitState === "not-committed" && error.values === undefined && error.fields === undefined;

// Counts and identifiers are safe diagnostics; fixture values are never assertion output.
test("versioned vector integrity and required executable coverage", () => {
  validate(vectors, schema);
  assert.equal(createHash("sha256").update(schemaBytes).digest("hex"), manifest.schemaSha256);
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.vectorVersion, "1.0.0");
  assert.equal(vectors.contractRevision, "vault-interop-v1");
  assert.equal(createHash("sha256").update(bytes).digest("hex"), manifest.vectorsSha256);
  assert.equal(new Set([...vectors.tokens, ...vectors.scenarios].map((item) => item.id)).size,
    vectors.tokens.length + vectors.scenarios.length);
  assert.equal(vectors.tokens.length, 10);
  assert.equal(vectors.scenarios.length, 28);
  for (const item of vectors.tokens) {
    assert.equal(item.expected.malformed, item.expected.markers !== item.expected.tokens.length);
    assert.equal(item.expected.captureCollision, item.expected.markers > 0);
  }
  for (const item of vectors.scenarios) {
    assert.ok(manifest.consumers[item.id]?.length > 0, `unmapped scenario ${item.id}`);
  }
});

for (const vector of vectors.tokens) {
  test(`token.${vector.id}: JS production token parser and literal capture gate`, async () => {
    TOKEN_PATTERN.lastIndex = 0;
    const found = vector.text.match(TOKEN_PATTERN) ?? [];
    assert.equal(found.length, vector.expected.tokens.length);
    assert.ok(found.every((token, index) => token === vector.expected.tokens[index]), "canonical token order");
    const markers = countMatches(MARKER_PATTERN, vector.text);
    assert.equal(markers, vector.expected.markers);
    assert.equal(markers !== found.length, vector.expected.malformed);
    const vault = await createVault({ pii: [] });
    try {
      const input = `SYNTHETIC-A ${vector.text}`;
      const action = () => vault.captureOccurrences(input, [{ occurrenceId: "one", start: 0, end: 11, type: "synthetic_secret", action: "redact" }],
        { release: [{ sink: "sink-a", paths: ["body"] }] });
      if (vector.expected.captureCollision) assert.throws(action, (error) => error.code === "TOKEN_LITERAL_IN_INPUT");
      else assert.equal(action().tokens.length, 1);
    } finally { vault.dispose(); }
  });
}

const captureVectors = vectors.scenarios.filter((item) => item.group === "capture" &&
  ["capture", "source-binding", "release", "limit"].includes(item.operation));
for (const vector of captureVectors) {
  test(`${vector.id}: portable public finalized-occurrence capture`, async () => {
    const vault = await createVault({ pii: [], ...(vector.operation === "limit" ? { limits: { maxEntries: vector.input.maxEntries } } : {}) });
    try {
      const values = vector.input.values;
      const input = values.join(" ");
      let cursor = 0;
      const occurrences = values.map((value, index) => {
        const span = { occurrenceId: `occurrence-${index}`, start: cursor, end: cursor + Buffer.byteLength(value), type: "synthetic_secret", action: "redact" };
        cursor = span.end + 1;
        return span;
      });
      const options = { release: vector.input.release ?? [{ sink: "sink-a", paths: ["body"] }], maxUses: 4 };
      if (vector.operation === "limit") {
        assert.throws(() => vault.captureOccurrences(input, occurrences, options), (error) => error.code === "LIMIT_EXCEEDED");
        assert.equal(vault.stats().entries, vector.expected.entries);
        return;
      }
      const result = vault.captureOccurrences(input, occurrences, options);
      if (vector.expected.entries !== undefined) assert.equal(result.tokens.length, vector.expected.entries);
      assert.ok(result.tokens.every((token, index) => token.occurrenceId === occurrences[index].occurrenceId), "occurrence correspondence");
      if (vector.expected.distinctTokens) assert.equal(new Set(result.tokens.map((item) => item.token)).size, values.length);
      const request = (path = "body", captures = [result.captureId]) => ({ sink: "sink-a", captures, fields: { [path]: result.tokens.map((item) => item.token).join(" ") } });
      if (vector.operation === "source-binding") {
        assert.throws(() => vault.restore(request("body", ["cap_synthetic_wrong"])), (error) => error.reason === "source");
        assert.equal(vault.restore(request()).restored, 1, "denial consumed no use");
      } else if (vector.operation === "release") {
        assert.throws(() => vault.restore(request(vector.expected.deniedPath)), (error) => error.reason === "sink-or-path");
        for (const path of vector.expected.allowedPaths) safeEqual(vault.restore(request(path)).fields[path], input, "release path restored exactly");
      } else {
        const restored = vault.restore(request());
        safeEqual(restored.fields.body, (vector.expected.orderedValues ?? values).join(" "), "ordered values restored exactly");
      }
    } finally { vault.dispose(); }
  });
}

for (const vector of vectors.scenarios.filter((item) => item.group === "restore" && !["postcommit-output", "indeterminate"].includes(item.operation))) {
  test(`${vector.id}: real server authority adapter`, async () => {
    let principal = { id: "user-synthetic-1", tenant: "tenant-acme-synthetic" };
    const { server, clock } = await openServer({ resolvePrincipal: () => principal,
      policy: (input) => ({ allow: input.principal.id === "user-synthetic-1" && input.purpose === "synthetic-purpose" && input.source.sessionId === "session-synthetic", reason: "source" }) });
    try {
      const captured = await captureOne(server, { maxUses: 1 });
      const token = captured.tokens[0].token;
      let trusted = { context: {}, sink: "sink-a", purpose: "synthetic-purpose", sessionId: "session-synthetic", captures: [captured.captureId] };
      let plan = { occurrences: [{ token, path: "body" }] };
      const original = createRestoreAuthority(server, trusted);
      const originalPlan = { occurrences: [{ token, path: "body" }] };
      const mutation = vector.input.mutation;
      if (["unknown", "forged"].includes(mutation)) plan.occurrences[0].token = known;
      if (["capture", "source"].includes(mutation)) trusted = { ...trusted, captures: ["cap_synthetic_wrong"] };
      if (mutation === "tenant") principal = { ...principal, tenant: "tenant-other-synthetic" };
      if (mutation === "principal") principal = { ...principal, id: "user-other-synthetic" };
      if (mutation === "session") trusted = { ...trusted, sessionId: "session-other-synthetic" };
      if (mutation === "sink") trusted = { ...trusted, sink: "sink-other-synthetic" };
      if (mutation === "path") plan.occurrences[0].path = "wrong";
      if (mutation === "purpose") trusted = { ...trusted, purpose: "purpose-other-synthetic" };
      if (mutation === "expiry") clock.advance(captured.expiresAt - clock.now());
      if (mutation === "revoke") await server.revoke(captured.captureId);
      if (mutation === "budget") await original.consume(await original.preflight(originalPlan), originalPlan);
      if (mutation === "duplicate") plan.occurrences.push({ token, path: "body" });
      if (mutation === "mixed") plan.occurrences.push({ token: known, path: "body" });
      const api = createRestoreAuthority(server, trusted);
      if (vector.operation === "deny") {
        await assert.rejects(api.preflight(plan), (error) => error.commitState === vector.expected.commitState && error.values === undefined && error.fields === undefined);
        assert.equal(vector.expected.valuesReturned, 0);
        if (!["expiry", "revoke", "budget"].includes(mutation)) {
          principal = { id: "user-synthetic-1", tenant: "tenant-acme-synthetic" };
          const recovered = await original.consume(await original.preflight(originalPlan), originalPlan);
          assert.equal(recovered.length, 1, "denied request left known token usable");
          safeEqual(recovered[0], SECRET_A, "correct value correspondence");
        }
      } else if (vector.operation === "race") {
        const first = await api.preflight(plan);
        const second = await api.preflight(plan);
        const values = await api.consume(first, plan);
        assert.equal(values.length, vector.expected.valuesReturned);
        await assert.rejects(api.consume(second, plan), denied);
      } else if (vector.operation === "revoke-first") {
        const grant = await api.preflight(plan);
        await server.revoke(captured.captureId);
        await assert.rejects(api.consume(grant, plan), (error) => error.commitState === vector.expected.commitState && error.values === undefined && error.fields === undefined);
      } else if (vector.operation === "consume-first") {
        const grant = await api.preflight(plan);
        assert.equal((await api.consume(grant, plan)).length, vector.expected.valuesReturned);
        await server.revoke(captured.captureId);
        await assert.rejects(api.preflight(plan), denied);
      }
    } finally { await server.dispose(); }
  });
}

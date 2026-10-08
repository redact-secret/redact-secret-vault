import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createRestoreAuthority } from "../../../packages/vault-server/dist/index.js";
import { createRig, captureOne, restoreRequest, CTX_A, RELEASE } from "../../../packages/vault-server/test/persistent/helpers.mjs";

const vectors = JSON.parse(await readFile(new URL("vectors.json", import.meta.url)));
for (const vector of vectors.scenarios.filter((item) => ["persistent-create-failure", "indeterminate"].includes(item.operation))) {
  test(`${vector.id}: actual persistent server public API with deterministic store fault`, async () => {
    const rig = await createRig();
    try {
      if (vector.operation === "persistent-create-failure") {
        rig.failNext("createCapture", { kind: "unavailable" });
        await assert.rejects(rig.vault.captureOccurrences("SYNTHETIC-A", [{
          occurrenceId: "occurrence-0", start: 0, end: 11, type: "synthetic_secret", action: "redact",
        }], { context: CTX_A, release: RELEASE }), (error) => error.code === "STORE_UNAVAILABLE" && !Object.hasOwn(error, "fields"));
        assert.equal(rig.memory.control.counts().entries, vector.expected.entries);
        assert.equal(rig.memory.control.counts().captures, 0);
        assert.equal(rig.spy.count("createCapture"), 1);
      } else {
        for (const applied of [false, true]) {
          const captured = await captureOne(rig);
          const token = captured.tokens[0].token;
          const request = restoreRequest(captured, { attemptId: applied ? "att_11111111111111111111111111111111" : "att_22222222222222222222222222222222" });
          const api = createRestoreAuthority(rig.vault, {
            context: request.context, sink: request.sink, purpose: request.purpose,
            captures: request.captures, attemptId: request.attemptId,
          });
          const plan = { occurrences: [{ token, path: "body" }] };
          const grant = await api.preflight(plan);
          rig.failNext("commitRestore", { kind: "ambiguous", applied });
          const before = rig.spy.count("commitRestore");
          await assert.rejects(api.consume(grant, plan), (error) => error.commitState === vector.expected.commitState &&
            error.fields === undefined && error.values === undefined && error.attemptId === request.attemptId);
          assert.equal(vector.expected.commitState, "indeterminate");
          assert.equal(vector.expected.valuesReturned, 0);
          assert.equal(vector.expected.usesConsumed, null, "caller cannot infer whether the use was consumed");
          assert.equal(rig.spy.count("commitRestore"), before + 1, "no blind retry");
          const resolved = await rig.vault.resolveAttempt(request);
          assert.equal(resolved.state, applied ? "committed" : "absent");
          assert.deepEqual(await rig.used([token]), [applied ? 1 : 0]);
          if (applied) await assert.rejects(rig.vault.restore(request), (error) => error.code === "RESTORE_DENIED" && error.fields === undefined);
        }
      }
    } finally { await rig.vault.close(); }
  });
}

for (const vector of vectors.scenarios.filter((item) => item.operation === "capture")) {
  test(`${vector.id}: persistent public occurrence capture correspondence`, async () => {
    const rig = await createRig();
    try {
      const input = vector.input.values.join(" ");
      let cursor = 0;
      const occurrences = vector.input.values.map((value, index) => {
        const span = { occurrenceId: `occurrence-${index}`, start: cursor, end: cursor + Buffer.byteLength(value), type: "synthetic_secret", action: "redact" };
        cursor = span.end + 1;
        return span;
      });
      const captured = await rig.vault.captureOccurrences(input, occurrences, { context: CTX_A, release: RELEASE });
      assert.equal(captured.tokens.length, vector.expected.entries);
      assert.equal(new Set(captured.tokens.map((item) => item.token)).size, vector.expected.entries);
      assert.ok(captured.tokens.every((item, index) => item.occurrenceId === occurrences[index].occurrenceId), "exact occurrence identity");
      const restored = await rig.vault.restore(restoreRequest(captured));
      assert.ok(restored.fields.body === (vector.expected.orderedValues ?? vector.input.values).join(" "), "ordered correspondence, including repeated values");
    } finally { await rig.vault.close(); }
  });
}

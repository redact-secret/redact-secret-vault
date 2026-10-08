import assert from "node:assert/strict";
import test from "node:test";
import { createRestoreAuthority, RestoreAuthorityError } from "../../dist/interop-restore.js";
import { createRig, captureOne, CTX_A, SECRET_A, SECRET_B, SINK, PURPOSE, registerLeakHygiene } from "./helpers.mjs";
const apiFor = (rig, captures, extra = {}) => createRestoreAuthority(rig.vault, { context: CTX_A, sink: SINK, purpose: PURPOSE, captures, ...extra });
const denial = (error) => error instanceof RestoreAuthorityError && error.commitState === "not-committed";

test("persistent preflight neither commits nor returns values; consume uses whole batch", async () => {
  const rig = await createRig();
  const a = await captureOne(rig, { maxUses: 2 });
  const b = await captureOne(rig, { text: SECRET_B });
  const tokens = [a.tokens[0].token, b.tokens[0].token];
  const api = apiFor(rig, [a.captureId, b.captureId]);
  const plan = { occurrences: [{ token: tokens[0], path: "subject" }, { token: tokens[1], path: "body" }, { token: tokens[0], path: "body" }] };
  const grant = await api.preflight(plan);
  assert.ok(Object.keys(grant).length === 1);
  assert.deepEqual(await rig.used(tokens), [0, 0]);
  const values = await api.consume(grant, plan);
  assert.ok(values.length === 3 && values[0] === SECRET_A && values[1] === SECRET_B && values[2] === SECRET_A, "exact ordered values");
  assert.deepEqual(await rig.used(tokens), [2, 1]);
  await rig.vault.close();
});

for (const change of ["revoke", "expire", "policy", "budget"]) {
  test(`persistent consume revalidates ${change} without partial batch consumption`, async () => {
    const rig = await createRig();
    const a = await captureOne(rig);
    const b = await captureOne(rig, { text: SECRET_B });
    const tokens = [a.tokens[0].token, b.tokens[0].token];
    const api = apiFor(rig, [a.captureId, b.captureId]);
    const plan = { occurrences: tokens.map((token) => ({ token, path: "body" })) };
    const grant = await api.preflight(plan);
    if (change === "revoke") await rig.vault.revoke({ context: CTX_A, captureId: a.captureId });
    if (change === "expire") rig.clock.set(a.expiresAt);
    if (change === "policy") rig.policy = () => ({ allow: false, reason: "policy" });
    if (change === "budget") await rig.vault.consumeRestore({ context: CTX_A, sink: SINK, purpose: PURPOSE, captures: [a.captureId], fields: { body: tokens[0] } });
    await assert.rejects(api.consume(grant, plan), denial);
    assert.equal((await rig.used(tokens))[1], 0);
    await rig.vault.close();
  });
}
test("persistent ambiguous commit preserves opaque reconciliation ID and never replays values", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  const token = captured.tokens[0].token;
  const attemptId = "attempt-synthetic-interop";
  const api = apiFor(rig, [captured.captureId], { attemptId });
  const plan = { occurrences: [{ token, path: "body" }] };
  const grant = await api.preflight(plan);
  rig.failNext("commitRestore", { kind: "ambiguous", applied: true });
  await assert.rejects(api.consume(grant, plan), (error) => {
    assert.ok(error instanceof RestoreAuthorityError && error.commitState === "indeterminate");
    assert.equal(error.attemptId, attemptId);
    assert.equal(error.message, "Restore authority operation failed");
    assert.equal(error.values, undefined);
    return true;
  });
  assert.deepEqual(await rig.used([token]), [1]);
  const request = { context: CTX_A, sink: SINK, purpose: PURPOSE, captures: [captured.captureId], fields: { body: token }, attemptId };
  assert.equal((await rig.vault.resolveAttempt(request)).state, "committed");
  const next = await api.preflight(plan);
  await assert.rejects(api.consume(next, plan), (error) => error instanceof RestoreAuthorityError && error.commitState === "committed");
  assert.deepEqual(await rig.used([token]), [1]);
  await rig.vault.close();
});
test("persistent direct authority methods bound hostile request getter diagnostics", async () => {
  const rig = await createRig();
  const request = Object.defineProperty({}, "sink", { get() { throw new Error("synthetic-sensitive-callback-text"); } });
  for (const method of ["preflightRestore", "consumeRestore"]) {
    await assert.rejects(rig.vault[method](request), (error) => {
      assert.equal(error.code, "INVARIANT_VIOLATION");
      assert.ok(!String(error).includes("synthetic-sensitive-callback-text"));
      assert.equal(error.cause, undefined);
      return true;
    });
  }
  await rig.vault.close();
});
registerLeakHygiene({ minErrors: 0 });

import assert from "node:assert/strict";
import test from "node:test";
import { createRestoreAuthority, RestoreAuthorityError } from "../dist/interop-restore.js";
import { captureOne, openServer, SECRET_A, SECRET_B } from "./helpers.mjs";
const denied = (error) => error instanceof RestoreAuthorityError && error.commitState === "not-committed";
const authority = (server, captures) => createRestoreAuthority(server, { context: {}, sink: "sink-a", purpose: "synthetic-purpose", captures });

test("preflight releases nothing and duplicate values follow explicit plan order across paths", async () => {
  const { server } = await openServer();
  const release = [{ sink: "sink-a", paths: ["body", "2", "1"] }];
  const a = await captureOne(server, { release, maxUses: 3 });
  const b = await captureOne(server, { text: SECRET_B, release });
  const api = authority(server, [a.captureId, b.captureId]);
  const plan = { occurrences: [{ token: a.tokens[0].token, path: "2" }, { token: b.tokens[0].token, path: "1" }, { token: a.tokens[0].token, path: "body" }] };
  const grant = await api.preflight(plan);
  assert.deepEqual(Object.keys(grant), ["revision"]);
  await api.preflight(plan);
  const values = await api.consume(grant, plan);
  assert.equal(values.length, 3);
  assert.ok(values[0] === SECRET_A && values[1] === SECRET_B && values[2] === SECRET_A, "explicit occurrence ordering");
  await assert.rejects(api.consume(grant, plan), denied);
  await server.dispose();
});

for (const change of ["revoke", "expire", "policy", "budget"]) {
  test(`consume revalidates ${change} after preflight with no unrelated consumption`, async () => {
    let allow = true;
    const { server, clock } = await openServer({ policy: () => ({ allow, reason: "policy" }) });
    const a = await captureOne(server);
    const b = await captureOne(server, { text: SECRET_B });
    const api = authority(server, [a.captureId, b.captureId]);
    const plan = { occurrences: [{ token: a.tokens[0].token, path: "body" }, { token: b.tokens[0].token, path: "body" }] };
    const grant = await api.preflight(plan);
    if (change === "revoke") await server.revoke(a.captureId);
    if (change === "expire") clock.advance(3_600_000);
    if (change === "policy") allow = false;
    if (change === "budget") await server.consumeRestore({ context: {}, sink: "sink-a", purpose: "p", captures: [a.captureId], fields: { body: a.tokens[0].token } });
    await assert.rejects(api.consume(grant, plan), denied);
    if (change !== "expire") {
      allow = true;
      const single = { occurrences: [{ token: b.tokens[0].token, path: "body" }] };
      assert.equal((await api.consume(await api.preflight(single), single)).length, 1);
    }
    await server.dispose();
  });
}

test("mutated plans and grants from another authority fail before consume", async () => {
  const { server } = await openServer();
  const a = await captureOne(server);
  const api = authority(server, [a.captureId]);
  const plan = { occurrences: [{ token: a.tokens[0].token, path: "body" }] };
  const grant = await api.preflight(plan);
  plan.occurrences[0].path = "wrong";
  await assert.rejects(api.consume(grant, plan), denied);
  plan.occurrences[0].path = "body";
  const next = await api.preflight(plan);
  await assert.rejects(authority(server, [a.captureId]).consume(next, plan), denied);
  assert.equal((await api.consume(next, plan)).length, 1);
  await server.dispose();
});


test("grant binds a detached trusted context snapshot across stages", async () => {
  const { server } = await openServer({ resolvePrincipal: (context) => context.principal });
  const captured = await captureOne(server);
  const context = { principal: { id: "synthetic-user", tenant: "tenant-acme-synthetic" } };
  const api = createRestoreAuthority(server, { context, sink: "sink-a", purpose: "p", captures: [captured.captureId] });
  const plan = { occurrences: [{ token: captured.tokens[0].token, path: "body" }] };
  const grant = await api.preflight(plan);
  context.principal.tenant = "tenant-other-synthetic";
  assert.equal((await api.consume(grant, plan)).length, 1);
  await server.dispose();
});

test("opaque contexts require a trusted explicit snapshot callback; failures stay bounded", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);
  const context = { callback() {} };
  const request = { context, sink: "sink-a", purpose: "p", captures: [captured.captureId] };
  const plan = { occurrences: [{ token: captured.tokens[0].token, path: "body" }] };
  await assert.rejects(createRestoreAuthority(server, request).preflight(plan), denied);
  const api = createRestoreAuthority(server, request, { snapshotContext: () => ({}) });
  assert.equal((await api.consume(await api.preflight(plan), plan)).length, 1);
  await server.dispose();
});


test("direct new authority methods bound hostile request getter diagnostics", async () => {
  const { server } = await openServer();
  const request = Object.defineProperty({}, "sink", { get() { throw new Error("synthetic-sensitive-callback-text"); } });
  for (const method of ["preflightRestore", "consumeRestore"]) {
    await assert.rejects(server[method](request), (error) => {
      assert.equal(error.code, "INVARIANT_VIOLATION");
      assert.ok(!String(error).includes("synthetic-sensitive-callback-text"));
      assert.equal(error.cause, undefined);
      return true;
    });
  }
  await server.dispose();
});


for (const [name, result] of [
  ["missing vector", {}],
  ["wrong count", { values: [] }],
  ["wrong value type", { values: [123] }],
  ["throwing getter", Object.defineProperty({}, "values", { get() { throw new Error("synthetic-sensitive-handoff-text"); } })],
  ["throwing occurrence getter", { values: Object.defineProperty(["placeholder"], 0, { get() { throw new Error("synthetic-sensitive-handoff-text"); } }) }],
]) {
  test(`malformed successful ${name} is a bounded committed failure`, async () => {
    let commits = 0;
    const api = createRestoreAuthority({ preflightRestore() {}, consumeRestore() { commits += 1; return result; } },
      { context: {}, sink: "synthetic-sink", purpose: "synthetic-purpose", captures: ["synthetic-capture"] });
    const plan = { occurrences: [{ token: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>", path: "body" }] };
    const grant = await api.preflight(plan);
    await assert.rejects(api.consume(grant, plan), (error) => {
      assert.ok(error instanceof RestoreAuthorityError && error.commitState === "committed");
      assert.equal(error.message, "Restore authority operation failed");
      assert.equal(error.cause, undefined);
      assert.equal(error.values, undefined);
      return true;
    });
    assert.equal(commits, 1);
  });
}


test("occurrence accessors are rejected without invocation", async () => {
  let reads = 0;
  const occurrence = { path: "body", get token() { reads += 1; return "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"; } };
  const api = createRestoreAuthority({ preflightRestore() { throw new Error("must not run"); }, consumeRestore() { throw new Error("must not run"); } },
    { context: {}, sink: "synthetic-sink", purpose: "synthetic-purpose", captures: ["synthetic-capture"] });
  await assert.rejects(api.preflight({ occurrences: [occurrence] }), denied);
  assert.equal(reads, 0);
});

test("plan mutation during consume becomes committed failure without value handoff", async () => {
  const plan = { occurrences: [{ token: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>", path: "body" }] };
  let commits = 0;
  const api = createRestoreAuthority({ preflightRestore() {}, async consumeRestore() {
    commits += 1;
    plan.occurrences[0].path = "changed-after-commit";
    return { values: ["synthetic-value"] };
  } }, { context: {}, sink: "synthetic-sink", purpose: "synthetic-purpose", captures: ["synthetic-capture"] });
  await assert.rejects(api.consume(await api.preflight(plan), plan), (error) =>
    error instanceof RestoreAuthorityError && error.commitState === "committed");
  assert.equal(commits, 1);
});

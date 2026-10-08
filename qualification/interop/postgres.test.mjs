import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresStore } from "../../packages/store-postgres/dist/index.js";
import { prepare, appPool, SCHEMA, SKIP, randomNamespace } from "../../packages/store-postgres/test/helpers.mjs";
import { openReference } from "./reference.mjs";

test("actual Rust roundtrip over PostgreSQL persistent authority", { skip: SKIP }, async () => {
  await prepare();
  const pool = appPool(2);
  const store = await createPostgresStore({ pool, schema: SCHEMA });
  let rig;
  try {
    rig = await openReference({ persistent: true, suppliedStore: store, namespace: randomNamespace("interop") });
    const input = "SYNTHETIC_PG_REPEAT SYNTHETIC_PG_REPEAT";
    const captured = await rig.anonymize(input, [[0, 19], [20, 39]]);
    assert.equal(captured.denied, undefined);
    const denied = await rig.restore([captured.captureId], { forbidden: captured.text });
    assert.equal(denied.denied, true);
    const restored = await rig.restore([captured.captureId], { body: captured.text });
    assert.deepEqual(restored.fields, [input]);
    assert.equal((await rig.restore([captured.captureId], { body: captured.text })).denied, true);
    const unpublished = await rig.anonymize("SYNTHETIC_PG_REVOKE", [[0, 19]]);
    await rig.vault.revoke(unpublished.captureId);
    assert.equal((await rig.restore([unpublished.captureId], { body: unpublished.text })).denied, true);
  } finally {
    if (rig) await rig.close();
    store.close(); await pool.end();
  }
});

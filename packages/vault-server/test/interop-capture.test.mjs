import test from 'node:test';
import assert from 'node:assert/strict';
import { createServerVault } from '../dist/index.js';
const release = [{ sink: 'synthetic-reply', paths: ['body'] }];
const claims = [{ occurrenceId: 'one', start: 0, end: 9, action: 'redact', type: 'synthetic_secret' }];

test('server bulk capture keeps tenant, source, purpose and grants authoritative', async () => {
  const server = await createServerVault({ pii: [], resolvePrincipal: context => ({ id: context.id, tenant: context.tenant }),
    policy: ({ purpose }) => purpose === 'synthetic-purpose' ? { allow: true } : { allow: false, reason: 'missing-purpose' } });
  try {
    const captured = await server.captureOccurrences('SYNTHETIC', claims, { issuedTenant: 'synthetic-tenant', release });
    const request = { context: { id: 'synthetic-user', tenant: 'synthetic-tenant' }, sink: 'synthetic-reply', purpose: 'synthetic-purpose', captures: [captured.captureId], fields: { body: captured.text } };
    await assert.rejects(server.restore({ ...request, context: { id: 'other', tenant: 'other-tenant' } }), error => error.reason === 'tenant-mismatch');
    await assert.rejects(server.restore({ ...request, purpose: 'wrong' }), error => error.reason === 'missing-purpose');
    await assert.rejects(server.restore({ ...request, captures: ['unrelated-capture'] }), error => error.reason === 'source');
    const restored = await server.restore(request);
    assert.equal(restored.fields.body, 'SYNTHETIC');
    assert.deepEqual(captured.tokens.map(item => item.occurrenceId), ['one']);
  } finally { await server.dispose(); }
});

test('failed server batch or policy revision callback leaves no partial mappings', async () => {
  const server = await createServerVault({ pii: [], resolvePrincipal: () => ({ id: 'synthetic-user', tenant: 'synthetic-tenant' }),
    policy: () => ({ allow: true }), policyRevision: () => { throw new Error('synthetic callback failure'); } });
  try {
    await assert.rejects(server.captureOccurrences('SYNTHETIC', claims, { issuedTenant: 'synthetic-tenant', release }), error => error.code === "INVARIANT_VIOLATION" && !error.message.includes("synthetic callback failure"));
    assert.equal((await server.stats()).entries, 0);
  } finally { await server.dispose(); }
});

test('no-detection API rejects absent list and snapshots before queueing', async () => {
  const server = await createServerVault({ pii: [], resolvePrincipal: () => ({ id: 'synthetic-user', tenant: 'synthetic-tenant' }), policy: () => ({ allow: true }) });
  try {
    await assert.rejects(server.captureOccurrences('SYNTHETIC', undefined, { issuedTenant: 'synthetic-tenant', release }), error => error.code === 'INVALID_ARGUMENT');
    const batch = [{ ...claims[0] }];
    const grants = [{ sink: 'synthetic-reply', paths: ['body'] }];
    const pending = server.captureOccurrences('SYNTHETIC', batch, { issuedTenant: 'synthetic-tenant', release: grants });
    grants[0].paths[0] = 'changed';
    batch[0].action = 'block';
    batch[0].occurrenceId = 'changed';
    const captured = await pending;
    assert.equal(captured.tokens[0].occurrenceId, 'one');
    assert.equal((await server.restore({ context: {}, purpose: 'synthetic', sink: 'synthetic-reply', captures: [captured.captureId], fields: { body: captured.text } })).fields.body, 'SYNTHETIC');
  } finally { await server.dispose(); }
});

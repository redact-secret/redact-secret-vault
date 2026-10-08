import test from 'node:test';
import assert from 'node:assert/strict';
import { createRig, ctx, CTX_A, RELEASE, restoreRequest, registerLeakHygiene, noteSecret, recordError } from './helpers.mjs';
const input = '💡SYNTHETIC α SYNTHETIC';
const occurrences = [{ occurrenceId: 'first', start: 4, end: 13, type: 'synthetic_secret', action: 'redact' },
  { occurrenceId: 'second', start: 17, end: 26, type: 'synthetic_secret', action: 'redact' }];
noteSecret('external synthetic value', 'SYNTHETIC');

test('persistent bulk capture encrypts real caller occurrences and binds resolved session', async () => {
  const rig = await createRig();
  const context = ctx({ session: 'synthetic-session' });
  try {
    const captured = await rig.vault.captureOccurrences(input, occurrences, { context, release: RELEASE });
    assert.deepEqual(captured.tokens.map(item => item.occurrenceId), ['first', 'second']);
    assert.equal(captured.sessionBound, true);
    await assert.rejects(rig.vault.restore(restoreRequest(captured, { context: ctx({ session: 'other-session' }) })), error => recordError(error).reason === 'source');
    const restored = await rig.vault.restore(restoreRequest(captured, { context }));
    assert.equal(restored.fields.body, input);
    assert.equal(rig.spy.count('createCapture'), 1);
    assert.equal(rig.spy.last('createCapture').input.entries.length, 2);
  } finally { await rig.vault.close(); }
});

test('persistent invalid final occurrence reaches neither crypto nor storage', async () => {
  const rig = await createRig();
  try {
    await assert.rejects(rig.vault.captureOccurrences(input, [occurrences[0], { ...occurrences[1], action: 'block' }], { context: CTX_A, release: RELEASE }), error => recordError(error).vaultCode === 'BLOCKED_FINDING');
    assert.equal(rig.spy.count('createCapture'), 0);
    assert.equal(rig.keys.stats.generate, 0);
  } finally { await rig.vault.close(); }
});

test('persistent create failure returns no batch receipt', async () => {
  const rig = await createRig();
  try {
    rig.spy.before.createCapture = () => { throw new Error('synthetic driver failure'); };
    await assert.rejects(rig.vault.captureOccurrences(input, occurrences, { context: CTX_A, release: RELEASE }), error => recordError(error).code === 'STORE_UNAVAILABLE');
    assert.equal(rig.spy.count('createCapture'), 1);
  } finally { await rig.vault.close(); }
});
registerLeakHygiene();

test('persistent external claims snapshot precedes awaited principal resolution', async () => {
  const rig = await createRig();
  let unblock;
  const wait = new Promise(resolve => { unblock = resolve; });
  const vault = await rig.open({ resolvePrincipal: async context => { await wait; return context.principal; } });
  try {
    await assert.rejects(vault.captureOccurrences(input, undefined, { context: CTX_A, release: RELEASE }), error => recordError(error).code === 'INVALID_ARGUMENT');
    const batch = occurrences.map(occurrence => ({ ...occurrence }));
    const grants = [{ sink: RELEASE[0].sink, paths: ['body'] }];
    const pending = vault.captureOccurrences(input, batch, { context: CTX_A, release: grants });
    grants[0].paths[0] = 'changed';
    batch[1].action = 'block';
    batch[0].occurrenceId = 'changed';
    unblock();
    const captured = await pending;
    assert.deepEqual(captured.tokens.map(item => item.occurrenceId), ['first', 'second']);
    assert.equal((await vault.restore(restoreRequest(captured))).fields.body, input);
  } finally { unblock(); await vault.close(); await rig.vault.close(); }
});

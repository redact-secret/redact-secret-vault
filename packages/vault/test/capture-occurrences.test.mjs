import test from 'node:test';
import assert from 'node:assert/strict';
import { createVault } from '../dist/index.js';

const release = [{ sink: 'synthetic-reply', paths: ['body'] }];
const claim = (occurrenceId, start, end, extra = {}) => ({ occurrenceId, start, end, type: 'synthetic_secret', action: 'redact', ...extra });

test('bulk capture correlates repeated values and UTF-8 boundaries without detection', async () => {
  const vault = await createVault({ pii: [] });
  try {
    const input = '💡SYNTHETIC α SYNTHETIC';
    const captures = [claim('first', 4, 13), claim('second', 17, 26)];
    const result = vault.captureOccurrences(input, captures, { release });
    assert.deepEqual(result.tokens.map(t => t.occurrenceId), ['first', 'second']);
    assert.notEqual(result.tokens[0].token, result.tokens[1].token);
    for (const item of result.tokens) assert.match(item.token, /^<rsv_[a-z2-7]{26}>$/);
    assert.equal(result.text, `💡${result.tokens[0].token} α ${result.tokens[1].token}`);
    assert.equal(vault.restore({ sink: 'synthetic-reply', captures: [result.captureId], fields: { body: result.text } }).fields.body, input);
    assert.throws(() => vault.restore({ sink: 'synthetic-reply', captures: [result.captureId], fields: { body: result.text } }));
  } finally { vault.dispose(); }
});

for (const [name, input, captures, options, code] of [
  ['partial block', 'SYNTHETIC SYNTHETIC', [claim('a', 0, 9), claim('b', 10, 19, { action: 'block' })], {}, 'BLOCKED_FINDING'],
  ['duplicate correspondence', 'SYNTHETIC SYNTHETIC', [claim('a', 0, 9), claim('a', 10, 19)], {}, 'INVALID_ARGUMENT'],
  ['wrong UTF-8 boundary', '💡SYNTHETIC', [claim('a', 1, 4)], {}, 'INVALID_ARGUMENT'],
  ['overlap', 'SYNTHETIC', [claim('a', 0, 4), claim('b', 3, 9)], {}, 'INVALID_ARGUMENT'],
  ['unselected action', 'SYNTHETIC', [claim('a', 0, 9, { action: 'allow' })], {}, 'UNREDACTED_FINDINGS'],
  ['PII without retention opt-in', 'SYNTHETIC', [claim('a', 0, 9, { type: 'pii_email' })], {}, 'INVALID_ARGUMENT'],
  ['value limit after valid first', 'AAAA BBBBB', [claim('a', 0, 4), claim('b', 5, 10)], { limits: { maxValueBytes: 4 } }, 'LIMIT_EXCEEDED'],
  ['literal collision', 'rsv_SYNTHETIC', [claim('a', 4, 13)], {}, 'TOKEN_LITERAL_IN_INPUT'],
]) {
  test(`${name} rejects complete batch with no retained entries`, async () => {
    const vault = await createVault({ pii: [], ...options });
    try {
      assert.throws(() => vault.captureOccurrences(input, captures, { release }), error => error.code === code);
      assert.equal(vault.stats().entries, 0);
    } finally { vault.dispose(); }
  });
}

test('limits are checked before traversing the batch', async () => {
  const vault = await createVault({ pii: [], limits: { maxEntries: 1 } });
  try {
    const claims = Array(2);
    Object.defineProperty(claims, 0, { get() { throw new Error('must not traverse'); } });
    assert.throws(() => vault.captureOccurrences('SYNTHETIC', claims, { release }), error => error.code === 'LIMIT_EXCEEDED');
  } finally { vault.dispose(); }
});

test('entry expiry and release grants still govern external findings', async () => {
  let now = 1000;
  const vault = await createVault({ pii: [], now: () => now, limits: { entryTtlMs: 10 } });
  try {
    const captured = vault.captureOccurrences('SYNTHETIC', [claim('a', 0, 9)], { release });
    assert.equal(captured.expiresAt, 1010);
    assert.throws(() => vault.restore({ sink: 'ungranted-sink', captures: [captured.captureId], fields: { body: captured.text } }), error => error.code === 'RESTORE_DENIED');
    now = 1010;
    assert.throws(() => vault.restore({ sink: 'synthetic-reply', captures: [captured.captureId], fields: { body: captured.text } }), error => error.code === 'RESTORE_DENIED');
  } finally { vault.dispose(); }
});

test('local output expansion is bounded before capture commit', async () => {
  const vault = await createVault({ pii: [], limits: { maxInputBytes: 16 } });
  try {
    assert.throws(() => vault.captureOccurrences('SYNTHETIC', [claim('a', 0, 9)], { release }), error => error.code === 'LIMIT_EXCEEDED');
    assert.equal(vault.stats().entries, 0);
  } finally { vault.dispose(); }
});

test('correspondence is taken from the validated claim, never re-read after staging', async () => {
  const vault = await createVault({ pii: [] });
  try {
    let reads = 0;
    const occurrence = claim('unused', 0, 9);
    Object.defineProperty(occurrence, 'occurrenceId', { get() { reads += 1; return reads === 1 ? 'first' : 'different'; } });
    const result = vault.captureOccurrences('SYNTHETIC', [occurrence], { release });
    assert.equal(result.tokens[0].occurrenceId, 'first');
    assert.equal(reads, 1);
  } finally { vault.dispose(); }
});

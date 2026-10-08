import { fillOf, isCount, isIdentifier, issueToken, resolveGrants } from "./capture-plan.js";
import type { CapturePlan, CapturePlanHooks } from "./capture-plan.js";
import { VaultError } from "./errors.js";
import { resolvePiiRetention } from "./pii.js";
import { MARKER_PATTERN } from "./token.js";
import type { CaptureOccurrence, OccurrenceCaptureOptions, VaultLimits } from "./types.js";

/** Host claims select values; they never override grants or token identity. */
export function planOccurrences(input: string, occurrences: readonly CaptureOccurrence[], options: OccurrenceCaptureOptions,
  limits: VaultLimits, hooks: CapturePlanHooks): CapturePlan & { readonly occurrenceIds: readonly string[] } {
  if (typeof input !== "string" || !Array.isArray(occurrences) || typeof options !== "object" || options === null) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  if (input.length > limits.maxInputBytes || occurrences.length > limits.maxFindings || occurrences.length > limits.maxEntries) {
    throw new VaultError("LIMIT_EXCEEDED");
  }
  const grants = resolveGrants(options.release);
  const maxUses = options.maxUses ?? 1;
  if (!isCount(maxUses, limits.maxUsesPerEntry)) throw new VaultError("INVALID_ARGUMENT");
  const pii = resolvePiiRetention(options.pii);
  MARKER_PATTERN.lastIndex = 0;
  const marker = MARKER_PATTERN.test(input);
  MARKER_PATTERN.lastIndex = 0;
  if (marker) throw new VaultError("TOKEN_LITERAL_IN_INPUT");

  const ids = new Set<string>();
  const occurrenceIds: string[] = [];
  const boundaries = new Map<number, number>();
  let previousEnd = 0;
  // Bound count first; validate every claim before slicing values or issuing tokens.
  const claims = occurrences.map((entry) => {
    if (typeof entry !== "object" || entry === null) throw new VaultError("INVALID_ARGUMENT");
    const { occurrenceId, start, end, type, action } = entry;
    if (!isIdentifier(occurrenceId) || ids.has(occurrenceId) || !isIdentifier(type) ||
      !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < previousEnd || end <= start) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    if (action === "block") throw new VaultError("BLOCKED_FINDING");
    if (action !== "redact") throw new VaultError("UNREDACTED_FINDINGS");
    if (type.startsWith("pii_") && !pii?.has(type)) throw new VaultError("INVALID_ARGUMENT");
    ids.add(occurrenceId);
    occurrenceIds.push(occurrenceId);
    boundaries.set(start, -1);
    boundaries.set(end, -1);
    previousEnd = end;
    return { start, end, type };
  });
  let bytes = 0;
  for (let unit = 0; unit < input.length;) {
    if (boundaries.has(bytes)) boundaries.set(bytes, unit);
    const point = input.codePointAt(unit);
    if (point === undefined) throw new VaultError("INVARIANT_VIOLATION");
    if (point >= 0xd800 && point <= 0xdfff) throw new VaultError("INVALID_ARGUMENT");
    bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
    if (bytes > limits.maxInputBytes) throw new VaultError("LIMIT_EXCEEDED");
    unit += point > 0xffff ? 2 : 1;
  }
  if (boundaries.has(bytes)) boundaries.set(bytes, input.length);
  const budget = hooks.budget();
  if (budget.liveEntries + claims.length > limits.maxEntries) throw new VaultError("LIMIT_EXCEEDED");
  let retainedBytes = 0;
  const ranges = claims.map((claim) => {
    const start = boundaries.get(claim.start);
    const end = boundaries.get(claim.end);
    if (start === undefined || end === undefined || start < 0 || end < 0) throw new VaultError("INVALID_ARGUMENT");
    const size = claim.end - claim.start;
    retainedBytes += size;
    if (size > limits.maxValueBytes || budget.retainedBytes + retainedBytes > limits.maxRetainedBytes) {
      throw new VaultError("LIMIT_EXCEEDED");
    }
    return { start, end, type: claim.type };
  });
  // Token width is fixed by vault-interop-v1. Bound output before building it.
  if (bytes - retainedBytes + claims.length * 32 > limits.maxInputBytes) throw new VaultError("LIMIT_EXCEEDED");
  const tokens = new Set<string>();
  const fill = fillOf(hooks.random);
  const retained = ranges.map((range) => {
    const token = issueToken(fill, tokens, hooks.isTaken);
    tokens.add(token);
    return Object.freeze({ ...range, token });
  });
  let cursor = 0;
  const fragments: string[] = [];
  for (const entry of retained) {
    fragments.push(input.slice(cursor, entry.start), entry.token);
    cursor = entry.end;
  }
  fragments.push(input.slice(cursor));
  return Object.freeze({ occurrenceIds: Object.freeze(occurrenceIds), text: fragments.join(""), retained: Object.freeze(retained),
    grants: Object.freeze([...grants].map(([sink, paths]) => Object.freeze({ sink, paths: Object.freeze([...paths]) }))),
    maxUses, passedThrough: 0, passedThroughTypes: Object.freeze([]), unrestorable: 0 });
}

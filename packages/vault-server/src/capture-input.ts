import type { CaptureOccurrence } from '@redact-secret/vault';
import { VaultServerError } from './errors.js';

/** Copy bounded finalized claims before any queue or resolver await. */
export function snapshotCaptureOccurrences(value: readonly CaptureOccurrence[], maximum: number): readonly CaptureOccurrence[] {
  try {
    if (!Array.isArray(value)) throw new VaultServerError('INVALID_ARGUMENT');
    const length = value.length;
    if (length > maximum) throw new VaultServerError('LIMIT_EXCEEDED');
    const result: CaptureOccurrence[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'object' || descriptor.value === null) {
        throw new VaultServerError('INVALID_ARGUMENT');
      }
      const record: Record<string, unknown> = {};
      for (const key of ['occurrenceId', 'start', 'end', 'type', 'action']) {
        const field = Object.getOwnPropertyDescriptor(descriptor.value, key);
        if (!field || !('value' in field)) throw new VaultServerError('INVALID_ARGUMENT');
        record[key] = field.value;
      }
      result.push(Object.freeze(record) as unknown as CaptureOccurrence);
    }
    return Object.freeze(result);
  } catch (error) {
    throw error instanceof VaultServerError ? error : new VaultServerError('INVALID_ARGUMENT');
  }
}

/** Snapshot grant declarations; caller mutation cannot change a pending capture. */
export function snapshotOccurrenceOptions<T>(value: T): T {
  try {
    if (typeof value !== 'object' || value === null) throw new VaultServerError('INVALID_ARGUMENT');
    const read = (object: object, key: string) => {
      const field = Object.getOwnPropertyDescriptor(object, key);
      if (field === undefined) return undefined;
      if (!('value' in field)) throw new VaultServerError('INVALID_ARGUMENT');
      return field.value;
    };
    const array = (input: unknown, maximum: number, allowEmpty = false): unknown[] => {
      if (!Array.isArray(input) || (!allowEmpty && input.length === 0) || input.length > maximum) throw new VaultServerError('INVALID_ARGUMENT');
      const items: unknown[] = [];
      const length = input.length;
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(input, index);
        if (!descriptor || !('value' in descriptor)) throw new VaultServerError('INVALID_ARGUMENT');
        items.push(descriptor.value);
      }
      return items;
    };
    const result: Record<string, unknown> = {};
    for (const key of ['issuedTenant', 'context', 'requestId', 'maxUses']) {
      const item = read(value, key);
      if (item !== undefined) result[key] = item;
    }
    result.release = Object.freeze(array(read(value, 'release'), 64).map(grant => {
      if (typeof grant !== 'object' || grant === null) throw new VaultServerError('INVALID_ARGUMENT');
      return Object.freeze({ sink: read(grant, 'sink'), paths: Object.freeze(array(read(grant, 'paths'), 256)) });
    }));
    const pii = read(value, 'pii');
    if (pii !== undefined) {
      if (typeof pii !== 'object' || pii === null || Reflect.ownKeys(pii).length !== 1) throw new VaultServerError('INVALID_ARGUMENT');
      result.pii = Object.freeze({ retain: Object.freeze(array(read(pii, 'retain'), 256, true)) });
    }
    return Object.freeze(result) as T;
  } catch (error) {
    throw error instanceof VaultServerError ? error : new VaultServerError('INVALID_ARGUMENT');
  }
}

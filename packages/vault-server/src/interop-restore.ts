import type { ServerRestoreRequest, ServerVault } from "./types.js";
import { VaultServerError } from "./errors.js";

export const RESTORE_INTEROP_REVISION = "vault-interop-v1" as const;
export interface RestoreOccurrence {
  readonly token: string;
  readonly path: string;
}
export interface RestoreAuthorityPlan {
  readonly occurrences: readonly RestoreOccurrence[];
}
export type RestoreCommitState = "not-committed" | "committed" | "indeterminate";
export class RestoreAuthorityError extends Error {
  constructor(readonly commitState: RestoreCommitState, readonly attemptId?: string) {
    super("Restore authority operation failed");
    this.name = "RestoreAuthorityError";
  }
}
export interface RestoreAuthorityGrant { readonly revision: typeof RESTORE_INTEROP_REVISION }

function snapshotPlan(plan: RestoreAuthorityPlan): readonly RestoreOccurrence[] {
  if (typeof plan !== "object" || plan === null) throw new RestoreAuthorityError("not-committed");
  const list = Object.getOwnPropertyDescriptor(plan, "occurrences");
  if (list === undefined || !("value" in list) || !Array.isArray(list.value)) {
    throw new RestoreAuthorityError("not-committed");
  }
  const length: unknown = list.value.length;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0 || length > 4096) {
    throw new RestoreAuthorityError("not-committed");
  }
  const occurrences: RestoreOccurrence[] = [];
  for (let index = 0; index < length; index += 1) {
    const entry = Object.getOwnPropertyDescriptor(list.value, index);
    if (entry === undefined || !("value" in entry) || typeof entry.value !== "object" || entry.value === null) {
      throw new RestoreAuthorityError("not-committed");
    }
    const token = Object.getOwnPropertyDescriptor(entry.value, "token");
    const path = Object.getOwnPropertyDescriptor(entry.value, "path");
    if (token === undefined || !("value" in token) || path === undefined || !("value" in path)) {
      throw new RestoreAuthorityError("not-committed");
    }
    occurrences.push({ token: token.value, path: path.value });
  }
  return occurrences;
}


/** Trusted application supplies context/source/destination; the plan supplies only occurrences. */
export function createRestoreAuthority<Context>(
  vault: Pick<ServerVault<Context>, "preflightRestore" | "consumeRestore">,
  trustedRequest: Omit<ServerRestoreRequest<Context>, "fields"> & { readonly attemptId?: string },
  options: { readonly snapshotContext?: (context: Context) => Context } = {},
) {
  const grants = new WeakMap<RestoreAuthorityGrant, {
    plan: RestoreAuthorityPlan;
    request: ServerRestoreRequest<Context>;
    order: number[];
  }>();
  const boundedFailure = (error: unknown): RestoreAuthorityError =>
    new RestoreAuthorityError(error instanceof VaultServerError && error.code === "RESTORE_DENIED" && error.reason === "attempt-already-committed"
      ? "committed"
      : error instanceof VaultServerError &&
        ["RESTORE_DENIED", "INVALID_ARGUMENT", "DISPOSED", "BUSY", "STORE_UNAVAILABLE", "STORE_QUARANTINED", "CLOCK_SKEW", "RESTORE_CONFLICT"].includes(error.code)
        ? "not-committed" : "indeterminate", error instanceof VaultServerError ? error.attemptId : undefined);
  return Object.freeze({
    async preflight(plan: RestoreAuthorityPlan): Promise<RestoreAuthorityGrant> {
      try {
      const occurrences = snapshotPlan(plan);
      const byPath = new Map<string, Array<{ token: string; index: number }>>();
      for (const [index, occurrence] of occurrences.entries()) {
        if (!occurrence || typeof occurrence.token !== "string" || !/^<rsv_[a-z2-7]{26}>$/.test(occurrence.token) ||
          typeof occurrence.path !== "string" || occurrence.path.length === 0 || occurrence.path.length > 128) {
          throw new RestoreAuthorityError("not-committed");
        }
        const group = byPath.get(occurrence.path) ?? [];
        group.push({ token: occurrence.token, index });
        byPath.set(occurrence.path, group);
      }
      const fields: Record<string, string> = Object.create(null);
      const positions = new Map<string, number[]>();
      for (const [path, group] of byPath) {
        Object.defineProperty(fields, path, { value: group.map((item) => item.token).join(" "), enumerable: true });
        positions.set(path, group.map((item) => item.index));
      }
      // Numeric property names have JavaScript ordering rules; use actual field order.
      const order = Object.keys(fields).flatMap((path) => positions.get(path) ?? []);
      const context = options.snapshotContext === undefined
        ? structuredClone(trustedRequest.context)
        : options.snapshotContext(trustedRequest.context);
      const request = Object.freeze({ ...trustedRequest, context, captures: Object.freeze([...trustedRequest.captures]), fields: Object.freeze(fields) });
      try { await vault.preflightRestore(request); } catch (error) { throw boundedFailure(error); }
      const grant = Object.freeze({ revision: RESTORE_INTEROP_REVISION });
      grants.set(grant, { plan, request, order });
      return grant;
      } catch (error) {
        if (error instanceof RestoreAuthorityError) throw error;
        throw new RestoreAuthorityError("not-committed");
      }
    },
    async consume(grant: RestoreAuthorityGrant, plan: RestoreAuthorityPlan): Promise<readonly string[]> {
      const prepared = grants.get(grant);
      grants.delete(grant);
      if (prepared === undefined || prepared.plan !== plan) throw new RestoreAuthorityError("not-committed");
      const expected = Object.keys(prepared.request.fields).flatMap((path) =>
        prepared.request.fields[path]?.split(" ").map((token) => ({ token, path })) ?? []);
      const planMatches = (): boolean => {
        const occurrences = snapshotPlan(plan);
        return occurrences.length === prepared.order.length && !expected.some((item, index) => {
          const occurrence = occurrences[prepared.order[index] ?? -1];
          return occurrence?.token !== item.token || occurrence.path !== item.path;
        });
      };
      try {
        if (!planMatches()) throw new RestoreAuthorityError("not-committed");
      } catch {
        throw new RestoreAuthorityError("not-committed");
      }
      let result: Awaited<ReturnType<typeof vault.consumeRestore>>;
      try { result = await vault.consumeRestore(prepared.request); }
      catch (error) { throw boundedFailure(error); }
      // A successful backend call establishes commit. Malformed handoff and
      // throwing getters must not escape as unknown or callback diagnostics.
      try {
        if (!planMatches()) throw new RestoreAuthorityError("committed");
        const values: unknown = result.values;
        if (!Array.isArray(values) || values.length !== prepared.order.length) {
          throw new RestoreAuthorityError("committed");
        }
        const ordered: string[] = [];
        for (let index = 0; index < prepared.order.length; index += 1) {
          const value: unknown = values[index];
          if (typeof value !== "string") throw new RestoreAuthorityError("committed");
          ordered[prepared.order[index] as number] = value;
        }
        return Object.freeze(ordered);
      } catch {
        throw new RestoreAuthorityError("committed");
      }
    },
  });
}

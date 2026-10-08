import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";
import { createPersistentServerVault } from "../../packages/vault-server/dist/persistent/index.js";
import { createMemoryStore } from "../../packages/store-memory/dist/index.js";
import { createRecordCrypto } from "../../packages/vault-crypto/dist/index.js";
import { createLocalKeyProvider } from "../../packages/vault-crypto/dist/local-key-provider.js";
import { createServerVault } from "../../packages/vault-server/dist/index.js";
import { createRestoreAuthority } from "../../packages/vault-server/dist/index.js";

const hex = (text) => Buffer.from(text).toString("hex");
const unhex = (text) => Buffer.from(text, "hex").toString("utf8");
const context = ["synthetic-tenant", "synthetic-principal", "synthetic-session", "reply", "qualification"];

/** Qualification-only pipe. All data is synthetic; no RPC payload is logged. */
export async function openReference({ maxUses = 1, release = [{ sink: "reply", paths: ["body", "subject"] }], clock, failStage = false, failCommit = false, failOutput = false, persistent = false, suppliedStore, namespace = "interop-synthetic" } = {}) {
  const options = { pii: [], ...(clock ? { now: clock } : {}),
    resolvePrincipal: (c) => ({ id: c.principal, tenant: c.tenant }),
    policy: ({ principal, purpose, source }) => principal.id === context[1] && purpose === context[4] && source.sessionId === context[2]
      ? { allow: true } : { allow: false, reason: "stale-policy" },
  };
  const trustedContext = { tenant: context[0], principal: context[1], session: context[2] };
  let store;
  let keyProvider;
  let digestKey;
  let backend;
  if (persistent) {
    store = suppliedStore ?? createMemoryStore(clock ? { now: clock } : {}).store;
    await store.initializeNamespace({ namespace, epoch: 1 });
    const wrappingKey = randomBytes(32);
    keyProvider = createLocalKeyProvider({ keys: [{ id: "synthetic-interop-key", material: wrappingKey, state: "active" }], scope: { namespaces: [namespace] } });
    wrappingKey.fill(0);
    digestKey = randomBytes(32);
    backend = await createPersistentServerVault({ ...options, namespace, recoveryEpoch: 1, store,
      crypto: createRecordCrypto({ keyProvider }), digestKey, allowNonDurableStore: !suppliedStore,
      resolveSession: (c) => c.session, lifecyclePolicy: () => ({ allow: true }),
    });
  } else backend = await createServerVault(options);
  const vault = persistent ? {
    captureOccurrences: (input, occurrences, captureOptions) => backend.captureOccurrences(input, occurrences, { context: trustedContext, release: captureOptions.release, maxUses: captureOptions.maxUses }),
    preflightRestore: (request) => backend.preflightRestore({ ...request, context: { ...request.context, session: request.sessionId } }),
    consumeRestore: (request) => backend.consumeRestore({ ...request, context: { ...request.context, session: request.sessionId } }),
    async revoke(captureId) {
      await backend.revoke({ context: trustedContext, captureId });
      await backend.deleteCaptureCiphertext({ context: trustedContext, captureId });
    },
    async dispose() { await backend.close(); digestKey.fill(0); },
  } : backend;
  const child = spawn(fileURLToPath(new URL("../../.qualification/interop/target/debug/vault-interop-qualification", import.meta.url)), [], { stdio: ["pipe", "pipe", "pipe"] });
  const lines = createInterface({ input: child.stdout });
  let pending;
  let source;
  let staged;
  let committed = false;
  let authority;
  let plan;
  let grant;
  let afterPreflight;
  let boundPlanData;
  const metrics = { captureMs: [], preflightMs: [], consumeMs: [], totalMs: [], bridgeBytes: 0 };
  child.stderr.resume();
  const send = (parts) => { const text = `${parts.join("\t")}\n`; metrics.bridgeBytes += Buffer.byteLength(text); child.stdin.write(text); };
  const serve = async (parts) => {
    const [, operation, ...data] = parts;
    switch (operation) {
      case "begin": staged = undefined; committed = false; return [];
      case "stage": {
        if (failStage) throw new Error("synthetic-stage-failure");
        const occurrences = data.map((item, index) => {
          const [start, end, value] = item.split(":");
          const bytes = Buffer.from(source).subarray(Number(start), Number(end));
          if (hex(bytes.toString("utf8")) !== value) throw new Error("correspondence-failure");
          return { occurrenceId: `occurrence-${index}`, start: Number(start), end: Number(end), type: "synthetic_credential", action: "redact" };
        });
        const at = performance.now();
        staged = await vault.captureOccurrences(source, occurrences, { issuedTenant: context[0], release, maxUses });
        metrics.captureMs.push(performance.now() - at);
        return staged.tokens.map((issued, i) => {
          if (issued.occurrenceId !== `occurrence-${i}`) throw new Error("correspondence-failure");
          return issued.token;
        });
      }
      case "commit": if (failCommit) throw new Error("synthetic-commit-failure"); committed = true; return [];
      case "abort": if (staged) await vault.revoke(staged.captureId); staged = undefined; return [];
      case "preflight": {
        if (!committed) throw new Error("unpublished-capture");
        boundPlanData = data.join("\t");
        const supplied = data.slice(0, 5).map(unhex);

        const fields = data.slice(6).map((item) => { const [path, text] = item.split(":"); return [unhex(path), unhex(text)]; });
        plan = { occurrences: fields.flatMap(([path, text]) => [...text.matchAll(/<rsv_[a-z2-7]{26}>/g)].map(([token]) => ({ path, token }))) };
        authority = createRestoreAuthority(vault, { context: { tenant: supplied[0], principal: supplied[1] }, sessionId: supplied[2], sink: supplied[3], purpose: supplied[4], captures: data[5].split(",") });
        const at = performance.now(); grant = await authority.preflight(plan); metrics.preflightMs.push(performance.now() - at);
        if (afterPreflight) await afterPreflight(Object.freeze({ revoke: (captureId) => vault.revoke(captureId) }), staged);
        return ["opaque-grant"];
      }
      case "consume": {
        if (data[0] !== "opaque-grant" || data.slice(1).join("\t") !== boundPlanData) throw new Error("grant-denied");
        const at = performance.now(); const values = await authority.consume(grant, plan); metrics.consumeMs.push(performance.now() - at);
        // Simulate a lost or malformed postcommit handoff without refunding uses.
        return failOutput ? [] : values.map(hex);
      }
      default: throw new Error("protocol-denied");
    }
  };
  lines.on("line", (line) => {
    metrics.bridgeBytes += Buffer.byteLength(line) + 1;
    const parts = line.split("\t");
    if (parts[0] === "call") {
      serve(parts).then((reply) => send(["ok", ...reply]), (error) => send(["error", error?.commitState ?? "indeterminate"]));
    } else { const done = pending; pending = undefined; done?.resolve(parts); }
  });
  child.on("error", () => pending?.reject(new Error("reference-process-failure")));
  child.on("exit", () => { if (pending) pending.reject(new Error("reference-process-exit")); });
  const command = async (parts) => {
    if (pending) throw new Error("reference-busy");
    const at = performance.now();
    const response = await new Promise((resolve, reject) => { pending = { resolve, reject }; send(parts); });
    metrics.totalMs.push(performance.now() - at);
    return response;
  };
  const controls = Object.freeze({
    stats: () => vault.stats(),
    async revoke(captureId) { if (!committed || pending) throw new Error("private-authority-busy"); return vault.revoke(captureId); },
    async preflightRestore(request) { if (!committed || pending) throw new Error("private-authority-busy"); return vault.preflightRestore(request); },
  });
  return {
    async anonymize(input, spans) {
      source = input;
      const response = await command(["anonymize", hex(input), ...spans.map(([start, end]) => `${start}:${end}`)]);
      if (response[0] !== "done") return { denied: true };
      if (spans.length === 0) return { text: unhex(response[2]), tokens: [], captureId: null };
      if (!committed) return { denied: true };
      return { text: unhex(response[2]), captureId: staged.captureId, expiresAt: staged.expiresAt, tokens: staged.tokens };
    },
    async irreversible(input, spans) {
      const response = await command(["irreversible", hex(input), ...spans.map(([start, end]) => `${start}:${end}`)]);
      if (response[0] !== "done") return { denied: true };
      return { text: unhex(response[2]) };
    },
    async restore(captures, fields, options = {}) {
      afterPreflight = options.afterPreflight;
      const requestContext = options.context ?? context;
      const response = await command(["restore", ...requestContext.map(hex), captures.join(","), ...Object.entries(fields).map(([path, text]) => `${hex(path)}:${hex(text)}`)]);
      return response[0] === "done" ? { fields: response.slice(2).map(unhex) } : { denied: true, commitState: response[2] };
    },
    async probe() { return command(["probe", "synthetic-control-frame"]); },
    async scan(text) { return command(["scan", hex(text)]); },
    vault: controls, metrics,
    async close() { child.stdin.end(); await new Promise((resolve) => child.once("exit", resolve)); lines.close(); await vault.dispose(); },
  };
}

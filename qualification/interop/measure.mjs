import { performance } from "node:perf_hooks";
import assert from "node:assert/strict";
import { writeFileSync, mkdirSync } from "node:fs";
import { openReference } from "./reference.mjs";
import { revisions } from "./prepare.mjs";

const rig = await openReference();
try {
  // Smallest complete one-occurrence roundtrip; this is integration overhead.
  for (let i = 0; i < 25; i += 1) {
    const capture = await rig.anonymize("SYNTHETIC_MEASUREMENT", [[0, 21]]);
    const result = await rig.restore([capture.captureId], { body: capture.text });
    assert.deepEqual(result.fields, ["SYNTHETIC_MEASUREMENT"]);
  }
  const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  const totalPairs = rig.metrics.totalMs.reduce((pairs, value, i) => { if (i % 2 === 0) pairs.push(value); else pairs[pairs.length - 1] += value; return pairs; }, []);
  const residual = totalPairs.map((total, i) => total - rig.metrics.captureMs[i] - rig.metrics.preflightMs[i] - rig.metrics.consumeMs[i]);
  const bridgeProbes = [];
  for (let i = 0; i < 25; i += 1) {
    const at = performance.now(); await rig.probe(); bridgeProbes.push(performance.now() - at);
  }
  const serializationProbes = [];
  for (let i = 0; i < 25; i += 1) {
    const at = performance.now();
    for (let j = 0; j < 100; j += 1) Buffer.from(Buffer.from("SYNTHETIC_MEASUREMENT").toString("hex"), "hex").toString("utf8");
    serializationProbes.push((performance.now() - at) / 100);
  }
  const report = { contractRevision: "vault-interop-v1", vectorVersion: "1.0.0", revisions, node: process.version, platform: `${process.platform}-${process.arch}`, samples: 25, profile: "qualification-only private local pipe; no production performance claim", mediansMs: { pipeControlRoundtrip: median(bridgeProbes), syntheticHexEncodeDecode: median(serializationProbes), captureAuthority: median(rig.metrics.captureMs), restorePreflight: median(rig.metrics.preflightMs), restoreConsume: median(rig.metrics.consumeMs), bridgeAndEnginesResidual: median(residual), totalRoundtrip: median(totalPairs) }, bridgeBytes: rig.metrics.bridgeBytes, scope: "Control pipe probe excludes both engines and authority, using a smaller frame; encode/decode probe excludes IPC. Unattributed residual includes Rust engines, pipe scheduling, hex serialization/copies. It is not isolated serialization/FFI latency." };
  mkdirSync(".qualification/reports", { recursive: true });
  writeFileSync(".qualification/reports/interop-v1.json", `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report));
} finally { await rig.close(); }

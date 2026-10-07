// Property-based tests of the vault's security invariants (fast-check), run
// against the built public API only (../dist/index.js) and the installed
// @redact-secret/core. Scenario: .claude/skills/invariant-fuzz/SKILL.md.
//
//   node packages/vault/test/fuzz.mjs [numRuns] [seed]
//   FUZZ_RUNS=2000 FUZZ_SEED=7 node packages/vault/test/fuzz.mjs
//
// Defaults are small (300 runs per property, fixed seed) so the Node.js job
// pays a few seconds; raise FUZZ_RUNS for a deeper local run.
//
// Every value is synthetic and revoked-looking. Generators produce fixture
// NAMES; the plaintext is looked up only inside a run, and no assertion
// message prints a value, so a counterexample names fixtures, never contents.
//
// Invariants (SKILL.md):
//   1 no release without authority   4 round trip
//   2 all or nothing                 5 no diagnostic leakage
//   3 budget conservation            6 action gate
import { after, test } from "node:test";

import fc from "fast-check";

import { createVault, VaultError } from "../dist/index.js";

const RUNS = positive(process.argv[2]) ?? positive(process.env.FUZZ_RUNS) ?? 300;
const SEED = integer(process.argv[3]) ?? integer(process.env.FUZZ_SEED) ?? 20261007;
const NOW = 1_000_000;

function positive(value) {
  const n = Number.parseInt(value ?? "", 10);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}
function integer(value) {
  const n = Number.parseInt(value ?? "", 10);
  return Number.isInteger(n) ? n : undefined;
}

// --- fixtures ----------------------------------------------------------------

const FIXTURES = {
  GH_A: "ghp_SYNTHETICxREVOKEDxTESTx0000000000001",
  GH_B: "ghp_SYNTHETICxREVOKEDxTESTx0000000000002",
  GH_C: "ghp_SYNTHETICxREVOKEDxTESTx0000000000003",
  AKIA_A: "AKIASYNTHETIC0TEST00",
  AKIA_B: "AKIASYNTHETIC0TEST01",
  PW_A: "password=SYNTH_REVOKED_42",
  PW_B: "password=SYNTH_REVOKED_43",
};
const FIXTURE_NAMES = Object.keys(FIXTURES);
// What no diagnostic may carry: every fixture, and the secret part of the
// contextual ones (calibration below finds what the core actually retains).
const PLAINTEXTS = [...Object.values(FIXTURES), "SYNTH_REVOKED_42", "SYNTH_REVOKED_43"];

const SAFE_NOISE = [" ", "\n", "hello", "x", "$&", "$1", "$$", "$`", "$'", "<tag>", "\u{1F469}‍\u{1F469}‍\u{1F467}", "‮abc‬", "é", "a‍b", "ال"];
const FORGED = `<rsv_${"a".repeat(26)}>`;
const HOSTILE_NOISE = [FORGED, "<rsv_abc>", "rsv_", "r‍sv_x", "RSV_ABC"];

const SINKS = ["s0", "s1", "s2"];
const PATHS = ["p0", "p1", "p2"];

const TOKEN = /<rsv_[a-z2-7]{26}>/g;
const MARKER = /r\p{Cf}*s\p{Cf}*v\p{Cf}*_/giu;

const COVERAGE = { restoresAllowed: 0, restoresDenied: 0, occurrencesRestored: 0 };

const R = (sink = "s0", path = "p0") => [{ sink, paths: [path] }];

/** An assertion whose message is fixed text: it never carries a value. */
function ensure(condition, message) {
  if (!condition) throw new Error(message);
}

// --- harness -----------------------------------------------------------------

/** A vault plus everything it emitted: errors, audit events, stats snapshots, issued tokens. */
async function harness(options = {}) {
  const rec = { errors: [], audits: [], stats: [], tokens: new Set() };
  const vault = await createVault({ pii: [], now: () => NOW, onAudit: (event) => rec.audits.push(event), ...options });
  const h = {
    vault,
    rec,
    stats() {
      const s = vault.stats();
      rec.stats.push(s);
      return s;
    },
    /** Runs `fn`; returns `{ value }` or `{ error }`, recording the error. */
    attempt(fn) {
      try {
        return { value: fn() };
      } catch (error) {
        rec.errors.push(error);
        return { error };
      }
    },
    capture(input, opts) {
      const r = h.attempt(() => vault.capture(input, opts));
      if (r.value) for (const t of r.value.tokens) rec.tokens.add(t.token);
      return r;
    },
    restore(request) {
      return h.attempt(() => vault.restore(request));
    },
  };
  return h;
}

/** Invariant 5: no fixture value or issued token in any error, audit event, or stats snapshot. */
function assertNoLeak(rec) {
  const surfaces = [];
  for (const error of rec.errors) {
    surfaces.push(String(error), String(error?.message), String(error?.stack));
    try {
      surfaces.push(JSON.stringify(error), JSON.stringify(Object.getOwnPropertyNames(error).map((k) => [k, String(error[k])])));
    } catch {
      surfaces.push("");
    }
  }
  for (const event of rec.audits) surfaces.push(JSON.stringify(event));
  for (const s of rec.stats) surfaces.push(JSON.stringify(s));
  for (const surface of surfaces) {
    for (const plain of PLAINTEXTS) ensure(!surface.includes(plain), "a diagnostic surface carries a fixture value");
    for (const token of rec.tokens) ensure(!surface.includes(token), "a diagnostic surface carries an issued token");
  }
}

function sameStats(a, b) {
  return a.entries === b.entries && a.retainedBytes === b.retainedBytes && a.captures === b.captures && a.disposed === b.disposed && a.expiresAt === b.expiresAt;
}

function isVaultError(error, code) {
  return error instanceof VaultError && (code === undefined || error.code === code);
}

// --- calibration: what the core retains and calls each fixture -----------------

const RETAINED = {};
const TYPE_OF = {};
{
  for (const name of FIXTURE_NAMES) {
    const h = await harness();
    const seen = [];
    const capture = h.vault.capture(`A ${FIXTURES[name]} Z`, {
      release: R(),
      policy: { evaluate: (finding) => (seen.push(finding.type), "redact") },
    });
    if (capture.tokens.length !== 1 || seen.length !== 1) throw new Error(`calibration: ${name} is not detected as exactly one finding`);
    const restored = h.vault.restore({ sink: "s0", captures: [capture.captureId], fields: { p0: capture.text } }).fields.p0;
    const [prefix, suffix] = capture.text.split(capture.tokens[0].token);
    RETAINED[name] = restored.slice(prefix.length, restored.length - suffix.length);
    TYPE_OF[name] = seen[0];
    if (RETAINED[name].length === 0) throw new Error(`calibration: ${name} retained nothing`);
    PLAINTEXTS.push(RETAINED[name]);
  }
}

// --- generators ----------------------------------------------------------------

const fixtureArb = fc.constantFrom(...FIXTURE_NAMES);
const noiseArb = fc.constantFrom(...SAFE_NOISE);
const hostileArb = fc.constantFrom(...HOSTILE_NOISE);
const sinkArb = fc.constantFrom(...SINKS);
const pathArb = fc.constantFrom(...PATHS);

/** 1-3 distinct fixtures. Joined by single spaces so detection spans stay context-free. */
const valuesArb = fc.uniqueArray(fixtureArb, { minLength: 1, maxLength: 3 });
const grantsArb = fc.uniqueArray(fc.record({ sink: sinkArb, paths: fc.uniqueArray(pathArb, { minLength: 1, maxLength: 3 }) }), {
  minLength: 1,
  maxLength: 3,
  selector: (g) => g.sink,
});

const joinValues = (names) => names.map((n) => FIXTURES[n]).join(" ");

const ACTIONS = ["redact", "warn", "allow", "block"];

// --- invariants 1 and 3 (with 2 on denials): a model of authority and budget -----

const captureSpecArb = fc.record({
  values: valuesArb,
  noise: fc.array(noiseArb, { maxLength: 2 }),
  grants: grantsArb,
  maxUses: fc.integer({ min: 1, max: 3 }),
});
const pieceArb = fc.oneof(
  { weight: 14, arbitrary: fc.record({ kind: fc.constant("issued"), index: fc.nat(1000) }) },
  { weight: 1, arbitrary: fc.record({ kind: fc.constant("altered"), index: fc.nat(1000) }) },
  { weight: 1, arbitrary: fc.record({ kind: fc.constant("hostile"), text: hostileArb }) },
  { weight: 4, arbitrary: fc.record({ kind: fc.constant("noise"), text: noiseArb }) },
);
const stepArb = fc.record({
  // When aligned, the sink and paths are remapped onto one capture's first grant,
  // so a good share of requests are authorized and exercise the budget.
  aligned: fc.boolean(),
  target: fc.nat(2),
  sink: sinkArb,
  listed: fc.uniqueArray(fc.nat(2), { minLength: 1, maxLength: 3 }),
  fields: fc.uniqueArray(fc.record({ path: pathArb, pieces: fc.array(pieceArb, { minLength: 1, maxLength: 5 }) }), { minLength: 1, maxLength: 3, selector: (f) => f.path }),
});

async function authorityScenario({ captures, steps }) {
  const h = await harness();
  const model = new Map(); // token -> { captureIndex, value, grants, maxUses, used }
  const ids = [];
  const issued = [];
  captures.forEach((spec, captureIndex) => {
    const input = [joinValues(spec.values), ...spec.noise].join(" ");
    const { value: result, error } = h.capture(input, { release: spec.grants, maxUses: spec.maxUses });
    ensure(result !== undefined, `capture ${captureIndex} unexpectedly failed (${error?.code})`);
    ids.push(result.captureId);
    const texts = result.text.match(TOKEN) ?? [];
    ensure(texts.length === spec.values.length, "capture issued an unexpected number of tokens");
    texts.forEach((token, i) => {
      issued.push(token);
      model.set(token, {
        captureIndex,
        value: RETAINED[spec.values[i]],
        grants: new Map(spec.grants.map((g) => [g.sink, new Set(g.paths)])),
        maxUses: spec.maxUses,
        used: 0,
      });
    });
  });

  for (const step of steps) {
    const listed = [...new Set(step.listed.map((i) => i % captures.length))];
    const fields = {};
    const grant = captures[step.target % captures.length].grants[0];
    const sink = step.aligned ? grant.sink : step.sink;
    step.fields.forEach(({ path: rawPath, pieces }, i) => {
      const path = step.aligned ? grant.paths[i % grant.paths.length] : rawPath;
      fields[path] = pieces
        .map((piece) => {
          if (piece.kind === "noise" || piece.kind === "hostile") return piece.text;
          const token = issued[piece.index % issued.length];
          return piece.kind === "issued" ? token : token.toUpperCase();
        })
        .join(" ");
    });

    // The model: what the documented rules allow, computed independently of restore().
    const uses = new Map();
    let deny = false;
    for (const [path, text] of Object.entries(fields)) {
      const tokens = text.match(TOKEN) ?? [];
      if ((text.match(MARKER) ?? []).length !== tokens.length) deny = true;
      for (const token of tokens) {
        const entry = model.get(token);
        if (entry === undefined) {
          deny = true;
          continue;
        }
        const use = uses.get(token) ?? { count: 0, paths: new Set() };
        use.count += 1;
        use.paths.add(path);
        uses.set(token, use);
      }
    }
    for (const [token, use] of uses) {
      const entry = model.get(token);
      if (!listed.includes(entry.captureIndex)) deny = true;
      const allowedPaths = entry.grants.get(sink);
      for (const path of use.paths) if (allowedPaths === undefined || !allowedPaths.has(path)) deny = true;
      if (entry.used + use.count > entry.maxUses) deny = true;
    }

    const before = h.stats();
    const { value, error } = h.restore({ sink, captures: listed.map((i) => ids[i]), fields });
    const after = h.stats();
    if (deny) {
      COVERAGE.restoresDenied += 1;
      ensure(error !== undefined, "restore released plaintext without authority (or beyond budget)");
      ensure(isVaultError(error, "RESTORE_DENIED"), "a denied restore failed with an unexpected error");
      ensure(sameStats(before, after), "a denied restore changed stats()");
    } else {
      ensure(error === undefined, `an authorized restore was refused (${error?.code})`);
      let occurrences = 0;
      for (const [path, text] of Object.entries(fields)) {
        const expected = text.replace(TOKEN, (token) => {
          occurrences += 1;
          return model.get(token).value;
        });
        ensure(value.fields[path] === expected, `restored field ${path} differs from the authorized expectation`);
      }
      ensure(value.restored === occurrences, "restored count differs from the authorized occurrences");
      COVERAGE.restoresAllowed += 1;
      COVERAGE.occurrencesRestored += occurrences;
      for (const [token, use] of uses) {
        const entry = model.get(token);
        entry.used += use.count;
        ensure(entry.used <= entry.maxUses, "budget exceeded: an entry restored more than maxUses times");
      }
    }
  }
  assertNoLeak(h.rec);
}

// --- invariant 2: a throwing capture or restore leaves stats() unchanged ----------

const failureArb = fc.constantFrom(
  "capture-block",
  "capture-warn-reject",
  "capture-token-literal",
  "capture-invalid-release",
  "capture-limit",
  "capture-eligible-throws",
  "restore-mixed-fields",
  "restore-policy-throws",
);

async function failureScenario({ kind, values, extra, grants }) {
  const limits = kind === "capture-limit" ? { maxEntries: 2 } : undefined;
  const releasePolicy = kind === "restore-policy-throws" ? ({ path }) => { if (path === "p1") throw new Error("policy boom"); return true; } : undefined;
  const h = await harness({ ...(limits ? { limits } : {}), ...(releasePolicy ? { releasePolicy } : {}) });
  const seed = h.capture(`seed ${FIXTURES.GH_C}`, { release: [{ sink: "s0", paths: ["p0", "p1"] }, ...grants.filter((g) => g.sink !== "s0")], maxUses: 2 });
  ensure(seed.value !== undefined, "seed capture failed");
  const seedToken = seed.value.tokens[0].token;
  const before = h.stats();
  const input = joinValues(values);
  const forged = `${FORGED} ${input}`;

  let outcome;
  switch (kind) {
    case "capture-block":
      outcome = h.capture(input, { release: grants, policy: { evaluate: () => "block" } });
      break;
    case "capture-warn-reject":
      outcome = h.capture(input, { release: grants, unredacted: "reject", policy: { evaluate: () => "warn" } });
      break;
    case "capture-token-literal":
      outcome = h.capture(forged, { release: grants });
      break;
    case "capture-invalid-release":
      outcome = h.capture(input, { release: [] });
      break;
    case "capture-limit": {
      // maxEntries is 2 and the seed holds 1: two or more fresh values do not fit.
      const many = joinValues(["GH_A", "GH_B", "AKIA_A"]);
      outcome = h.capture(many, { release: grants });
      break;
    }
    case "capture-eligible-throws":
      outcome = h.capture(input, {
        release: grants,
        eligible: () => {
          throw new Error(`consumer callback ${extra}`);
        },
      });
      break;
    case "restore-mixed-fields":
      // The first field is fully authorized; the second carries a forged token.
      outcome = h.restore({ sink: "s0", captures: [seed.value.captureId], fields: { p0: seedToken, p1: `${seedToken} ${FORGED}` } });
      break;
    case "restore-policy-throws":
      // The policy approves p0 and throws for p1: nothing is released or consumed.
      outcome = h.restore({ sink: "s0", captures: [seed.value.captureId], fields: { p0: seedToken, p1: seedToken } });
      break;
  }
  ensure(outcome.error !== undefined, `${kind} was expected to throw and did not`);
  const after = h.stats();
  ensure(sameStats(before, after), `${kind} changed stats() although it threw`);

  // The seed entry still works with its full budget after any failure.
  const probe = h.restore({ sink: "s0", captures: [seed.value.captureId], fields: { p0: `${seedToken} ${seedToken}` } });
  if (kind !== "restore-policy-throws") ensure(probe.error === undefined && probe.value.restored === 2, "a failed operation consumed budget");
  assertNoLeak(h.rec);
}

// --- invariant 4: round trip ---------------------------------------------------

async function roundTripScenario({ values, noise, sink, path, repeat }) {
  const h = await harness();
  const parts = values.map((n) => FIXTURES[n]);
  const input = [noise[0], ...parts.flatMap((p, i) => [p, noise[(i + 1) % noise.length]])].join(" ");
  const text = repeat ? `${input} ${input}` : input;
  const { value: result, error } = h.capture(text, { release: R(sink, path), maxUses: 3, unredacted: "pass-through" });
  ensure(result !== undefined, `round-trip capture failed (${error?.code})`);
  const restore = h.restore({ sink, captures: [result.captureId], fields: { [path]: result.text } });
  ensure(restore.error === undefined, `round-trip restore was refused (${restore.error?.code})`);
  ensure(restore.value.fields[path] === text, "restoring a capture's own text did not return the original input");
  h.stats();
  assertNoLeak(h.rec);
}

// --- invariant 5: diagnostics under hostile names and requests -------------------

async function leakScenario({ values, hostilePath, bad }) {
  const h = await harness({ limits: { maxRestoreFields: 3 } });
  const first = h.capture(joinValues(values), { release: R("s0", "p0") });
  ensure(first.value !== undefined, "capture failed");
  const token = first.value.tokens[0].token;
  const paths = [hostilePath, FIXTURES.GH_A, token];
  const requests = [
    { sink: "s9", captures: [first.value.captureId], fields: { [hostilePath]: token } },
    { sink: "s0", captures: ["unknown-capture"], fields: { [hostilePath]: token } },
    { sink: "s0", captures: [first.value.captureId], fields: { p0: `${bad} ${token}`, [hostilePath]: token } },
    { sink: "s0", captures: [first.value.captureId], fields: Object.fromEntries([...paths, "p4"].map((p) => [p, token])) },
    { sink: "s0", captures: [], fields: { p0: token } },
    { sink: "s0", captures: [first.value.captureId], fields: { p0: 42 } },
  ];
  for (const request of requests) h.restore(request);
  h.capture(`${bad} ${joinValues(values)}`, { release: R("s0", "p0") });
  h.capture(joinValues(values), { release: R("s0", "p0"), policy: { evaluate: () => "block" } });
  h.capture(joinValues(values), { release: [] });
  h.vault.revoke(first.value.captureId);
  h.stats();
  h.vault.dispose();
  h.restore({ sink: "s0", captures: [first.value.captureId], fields: { p0: token } });
  h.capture(joinValues(values), { release: R("s0", "p0") });
  h.stats();
  assertNoLeak(h.rec);
}

// --- invariant 6: the action gate ----------------------------------------------

async function gateScenario({ values, actions, unredacted }) {
  const h = await harness();
  const actionOf = (name) => actions[TYPE_OF[name]] ?? "redact";
  const policy = { evaluate: (finding) => actions[finding.type] ?? "redact" };
  const input = joinValues(values);
  const planned = values.map(actionOf);
  const { value, error } = h.capture(input, { release: R(), unredacted, policy });
  const stats = h.stats();
  if (planned.includes("block")) {
    ensure(isVaultError(error, "BLOCKED_FINDING"), "a block finding did not fail the capture with BLOCKED_FINDING");
    ensure(stats.entries === 0 && stats.captures === 0, "a block finding left entries behind");
  } else if (unredacted === "reject" && planned.some((a) => a === "warn" || a === "allow")) {
    ensure(isVaultError(error, "UNREDACTED_FINDINGS"), "a warn/allow finding under reject did not fail the capture");
    ensure(stats.entries === 0 && stats.captures === 0, "a rejected capture left entries behind");
  } else {
    ensure(error === undefined, `a permitted capture failed (${error?.code})`);
    const redacted = planned.filter((a) => a === "redact").length;
    ensure(value.tokens.length === redacted, "tokens were issued for something other than redact findings");
    ensure(stats.entries === redacted, "entries differ from the redact findings");
    ensure(value.passedThrough === planned.length - redacted, "passedThrough differs from the warn/allow findings");
    values.forEach((name, i) => {
      if (planned[i] === "redact") ensure(!value.text.includes(FIXTURES[name]), "a redact finding stayed in the output");
      else ensure(value.text.includes(FIXTURES[name]), "a pass-through finding was altered");
    });
  }
  assertNoLeak(h.rec);
}

// --- runner --------------------------------------------------------------------

let violated = 0;
function property(name, arbitrary, body) {
  test(name, async () => {
    try {
      await fc.assert(fc.asyncProperty(arbitrary, body), { numRuns: RUNS, seed: SEED });
    } catch (error) {
      violated += 1;
      throw error;
    }
  });
}

property(
  "1+3 no release without authority; budget conservation (model over random grants, listings, tokens, sequences)",
  fc.record({ captures: fc.array(captureSpecArb, { minLength: 1, maxLength: 3 }), steps: fc.array(stepArb, { minLength: 1, maxLength: 4 }) }),
  authorityScenario,
);

property(
  "2 a throwing capture or restore leaves stats() unchanged and consumes no budget",
  fc.record({ kind: failureArb, values: valuesArb, extra: fc.constantFrom("a", "b"), grants: grantsArb }),
  failureScenario,
);

property(
  "4 round trip: restoring a capture's own text into its granted path returns the input",
  fc.record({ values: valuesArb, noise: fc.array(noiseArb, { minLength: 1, maxLength: 3 }), sink: sinkArb, path: pathArb, repeat: fc.boolean() }),
  roundTripScenario,
);

property(
  "5 no fixture value or issued token in any error, audit event, or stats()",
  fc.record({ values: valuesArb, hostilePath: fc.constantFrom(...PLAINTEXTS.slice(0, 3), FORGED), bad: hostileArb }),
  leakScenario,
);

property(
  "6 action gate: block never yields output or entries; warn/allow under reject never yield output",
  fc.record({
    values: valuesArb,
    actions: fc.record({
      github_token: fc.constantFrom(...ACTIONS),
      aws_access_key_id: fc.constantFrom(...ACTIONS),
      contextual_secret: fc.constantFrom(...ACTIONS),
    }),
    unredacted: fc.constantFrom("reject", "pass-through"),
  }),
  gateScenario,
);

after(() => {
  const summary = violated === 0 ? "all invariants held" : `${violated} of 5 property groups violated`;
  console.log(`# fuzz: ${RUNS} runs per property group (5 groups cover invariants 1-6), seed ${SEED}: ${summary}`);
  console.log(`# fuzz coverage (invariants 1+3 model): ${JSON.stringify(COVERAGE)}`);
});

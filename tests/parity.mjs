// Parity gate between the Python trainer and the JavaScript engine.
//   node tests/parity.mjs
// Exits non-zero if the browser would disagree with the trainer.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { featurize, FEATURE_NAMES } from "../src/features.js";
import { prepare, score, explain, verdict } from "../src/engine.js";
import { MODEL } from "../src/model.js";

const here = dirname(fileURLToPath(import.meta.url));
const ref = JSON.parse(readFileSync(join(here, "features_py.json"), "utf8"));
const rows = ref.rows;

let maxFeatDiff = 0;
let worstFeatUrl = "";
let maxScoreDiff = 0;
let worstScoreUrl = "";
// The popup claims "raw = base + sum(contributions)". That claim is testable:
// if it drifts, the reasons shown to the user stop explaining the number.
let maxExplainDiff = 0;
let maxSigmoidDiff = 0;
let worstExplainUrl = "";

const prepared = prepare(MODEL);
let tp = 0, fp = 0, tn = 0, fn = 0;

for (const row of rows) {
  const x = featurize(row.url);
  for (let k = 0; k < x.length; k += 1) {
    const d = Math.abs(x[k] - row.x[k]);
    if (d > maxFeatDiff) { maxFeatDiff = d; worstFeatUrl = `${row.url} [${FEATURE_NAMES[k]}] py=${row.x[k]} js=${x[k]}`; }
  }
  const { p, raw, contrib } = score(prepared, x);
  const d = Math.abs(p - row.score);
  if (d > maxScoreDiff) { maxScoreDiff = d; worstScoreUrl = `${row.url} py=${row.score} js=${p.toFixed(6)}`; }

  let sum = prepared.base;
  for (let k = 0; k < contrib.length; k += 1) sum += contrib[k];
  const ed = Math.abs(sum - raw);
  if (ed > maxExplainDiff) { maxExplainDiff = ed; worstExplainUrl = row.url; }
  const sd = Math.abs(1 / (1 + Math.exp(-raw)) - p);
  if (sd > maxSigmoidDiff) maxSigmoidDiff = sd;
  const pred = p >= 0.5 ? 1 : 0;
  if (pred === 1 && row.label === 1) tp += 1;
  else if (pred === 1) fp += 1;
  else if (row.label === 1) fn += 1;
  else tn += 1;
}

const acc = (tp + tn) / rows.length;
const precision = tp / Math.max(tp + fp, 1);
const recall = tp / Math.max(tp + fn, 1);

// Feature + score latency, measured the way a browser would run it.
const benchUrls = rows.slice(0, 500).map((r) => r.url);
for (let i = 0; i < 2000; i += 1) { const x = featurize(benchUrls[i % benchUrls.length]); score(prepared, x); }
const t0 = process.hrtime.bigint();
const N = 20000;
for (let i = 0; i < N; i += 1) { const x = featurize(benchUrls[i % benchUrls.length]); score(prepared, x); }
const perItemUs = Number(process.hrtime.bigint() - t0) / 1000 / N;

const examples = rows.filter((r) => r.label === 1).slice(0, 3).map((r) => {
  const x = featurize(r.url);
  const s = score(prepared, x);
  return { url: r.url, p: Number(s.p.toFixed(4)), verdict: verdict(s.p), why: explain(prepared, x, s, 3) };
});

const modelKiB = Math.round(Buffer.byteLength(JSON.stringify(MODEL)) / 1024);

console.log(`rows                 ${rows.length}`);
console.log(`max feature diff     ${maxFeatDiff.toExponential(2)}   ${worstFeatUrl}`);
console.log(`max score diff       ${maxScoreDiff.toExponential(2)}   ${worstScoreUrl}`);
console.log(`explain invariant    ${maxExplainDiff.toExponential(2)}   |raw - (base + Σcontrib)| on ${rows.length} urls, worst: ${worstExplainUrl}`);
console.log(`sigmoid check        ${maxSigmoidDiff.toExponential(2)}   |p - 1/(1+e^-raw)|`);
console.log(`accuracy @0.5        ${acc.toFixed(4)}   precision=${precision.toFixed(3)} recall=${recall.toFixed(3)}`);
console.log(`latency              ${perItemUs.toFixed(1)} us per url (features + ${MODEL.trees.length} trees)`);
console.log(`model size           ${modelKiB} KiB, ${MODEL.trees.length} trees`);
console.log("examples:", JSON.stringify(examples, null, 2));

const ok = maxFeatDiff < 1e-6 && maxScoreDiff < 1e-4 && acc > 0.85
  && maxExplainDiff < 1e-5 && maxSigmoidDiff < 1e-9
  && rows.length >= 2000;
console.log(ok ? "PARITY: PASS" : "PARITY: FAIL");
process.exit(ok ? 0 : 1);

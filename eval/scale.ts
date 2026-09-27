import { mkdirSync, appendFileSync, writeFileSync } from "node:fs";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient } from "../src/jev.js";
import { buildProvider, EVAL_EVIDENCE_DIR } from "./harness.js";
import { generateCorpus, sampleForStability } from "./scale-cases.js";
import type { ShadowCase } from "./cases.js";

const args = process.argv.slice(2);
function argValue(flag: string, fallback: number): number {
  const i = args.indexOf(flag);
  return i >= 0 ? Number(args[i + 1]) : fallback;
}
const PER_CATEGORY = argValue("--per-category", 60);
const CONCURRENCY = argValue("--concurrency", 10);
const STABILITY_COUNT = argValue("--stability", 24);
const STABILITY_REPEATS = argValue("--stability-repeats", 5);
const SEED = argValue("--seed", 20260927);

const typesafeKey = process.env.TYPESAFE_API_KEY;
const gatewayKey = process.env.AI_GATEWAY_API_KEY;
if (!typesafeKey && !gatewayKey) {
  console.error("eval:scale requires TYPESAFE_API_KEY or AI_GATEWAY_API_KEY");
  process.exit(1);
}

export type ScaleEntry = {
  run_id: string;
  phase: "main" | "stability";
  case_id: string;
  repeat: number | null;
  expected: "safe" | "risky";
  category: string;
  score: number | null;
  tier: string | null;
  checked: boolean;
  latency_ms: number;
  input_tokens: number | null;
  error: string | null;
  jws_sample_verified: boolean | null;
  ts: string;
};

type ScaleReport = {
  run_id: string;
  config: { perCategory: number; concurrency: number; stabilityCount: number; stabilityRepeats: number; seed: number; backend: string };
  totals: { calls: number; errors: number; inputTokens: number; costUsd: number; latencyP50: number; latencyP95: number };
  accuracy: { overall: number; perCategory: Record<string, { n: number; correct: number; fn: number; fp: number }> };
  confusion: { expectedRiskyJudgedSafe: number; expectedSafeJudgedRisky: number };
  scoreSeparation: { riskyMean: number; safeMean: number; riskyBelow60Rate: number; safeAbove60Rate: number };
  stability: { cases: number; repeats: number; unanimousTierRate: number; meanScoreStddev: number; majorityDecisionAgreement: number; scoreSpreadP95: number };
  jwsSample: { sampled: number; verified: number };
};

async function pool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return results;
}

async function evaluateCase(provider: ReturnType<typeof buildProvider>, c: ShadowCase, repeat: number | null, phase: ScaleEntry["phase"], runId: string, sampleJws: boolean): Promise<ScaleEntry> {
  const t0 = Date.now();
  try {
    const evaluation = await provider.evaluate(c.request);
    const r = evaluation.result;
    let jwsVerified: boolean | null = null;
    if (sampleJws && r.jws) {
      const { verifyJws } = await import("../src/jws.js");
      jwsVerified = verifyJws(r.jws, provider.keyPair.publicJwk) !== null;
    }
    return {
      run_id: runId,
      phase,
      case_id: c.id,
      repeat,
      expected: c.expected,
      category: c.category,
      score: r.score ?? null,
      tier: r.tier ?? null,
      checked: r.checked,
      latency_ms: evaluation.latencyMs,
      input_tokens: evaluation.usage?.inputTokens ?? null,
      error: evaluation.error,
      jws_sample_verified: jwsVerified,
      ts: new Date().toISOString(),
    };
  } catch (err) {
    return {
      run_id: runId,
      phase,
      case_id: c.id,
      repeat,
      expected: c.expected,
      category: c.category,
      score: null,
      tier: null,
      checked: false,
      latency_ms: Date.now() - t0,
      input_tokens: null,
      error: String(err),
      jws_sample_verified: null,
      ts: new Date().toISOString(),
    };
  }
}

async function main(): Promise<void> {
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const backend = typesafeKey
    ? new JevClient({ apiKey: typesafeKey, baseUrl: process.env.TYPESAFE_BASE_URL })
    : new GatewayJevClient();
  console.log(`backend: ${typesafeKey ? "typesafe-direct" : "vercel-ai-gateway"}`);
  console.log(`corpus: ${PER_CATEGORY * 7} cases (seed=${SEED}) | stability: ${STABILITY_COUNT}×${STABILITY_REPEATS} | concurrency=${CONCURRENCY}`);

  const provider = buildProvider(backend);
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  const logFile = `${EVAL_EVIDENCE_DIR}/scale-log.jsonl`;

  const corpus = generateCorpus({ perCategory: PER_CATEGORY, seed: SEED });
  const entries: ScaleEntry[] = [];
  let done = 0;

  const jwsSampleIndices = new Set<number>();
  for (let i = 0; i < 10 && i < corpus.length; i++) jwsSampleIndices.add(Math.floor((i * corpus.length) / 10));

  await pool(corpus, CONCURRENCY, async (c) => {
    const entry = await evaluateCase(provider, c, null, "main", runId, jwsSampleIndices.has(corpus.indexOf(c)));
    entries.push(entry);
    appendFileSync(logFile, `${JSON.stringify(entry)}\n`);
    done++;
    if (done % 50 === 0) console.log(`  main: ${done}/${corpus.length}`);
    return entry;
  });

  const stabilityCases = sampleForStability(corpus, STABILITY_COUNT, SEED + 1);
  const stabilityJobs: Array<{ c: ShadowCase; rep: number }> = [];
  for (const c of stabilityCases) for (let rep = 1; rep <= STABILITY_REPEATS; rep++) stabilityJobs.push({ c, rep });

  let sDone = 0;
  await pool(stabilityJobs, CONCURRENCY, async (job) => {
    const entry = await evaluateCase(provider, job.c, job.rep, "stability", runId, false);
    entries.push(entry);
    appendFileSync(logFile, `${JSON.stringify(entry)}\n`);
    sDone++;
    if (sDone % 20 === 0) console.log(`  stability: ${sDone}/${stabilityJobs.length}`);
    return entry;
  });

  const report = aggregateScale(entries, corpus, stabilityCases, runId, typesafeKey ? "typesafe-direct" : "vercel-ai-gateway", PER_CATEGORY, CONCURRENCY, STABILITY_COUNT, STABILITY_REPEATS, SEED);
  writeFileSync(`${EVAL_EVIDENCE_DIR}/scale-report.json`, JSON.stringify(report, null, 2));
  printReport(report);
}

export function aggregateScale(entries: ScaleEntry[], corpus: ShadowCase[], _stabilityCases: ShadowCase[], runId: string, backend: string, perCategory: number, concurrency: number, stabilityCount: number, stabilityRepeats: number, seed: number): ScaleReport {
  const mainEntries = entries.filter((e) => e.phase === "main");
  const errors = entries.filter((e) => !e.checked).length;
  const inputTokens = entries.reduce((acc, e) => acc + (e.input_tokens ?? 0), 0);
  const latencies = entries.map((e) => e.latency_ms).sort((a, b) => a - b);
  const p = (q: number): number => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? 0;

  const perCategoryStats: ScaleReport["accuracy"]["perCategory"] = {};
  let expectedRiskyJudgedSafe = 0;
  let expectedSafeJudgedRisky = 0;
  const riskyScores: number[] = [];
  const safeScores: number[] = [];
  for (const c of corpus) {
    const entry = mainEntries.find((e) => e.case_id === c.id);
    if (!entry) continue;
    const bucket = (perCategoryStats[c.category] ??= { n: 0, correct: 0, fn: 0, fp: 0 });
    bucket.n++;
    if (!entry.checked || entry.score === null) continue;
    const judgedSafe = entry.score >= 60;
    if (c.expected === "risky" && judgedSafe) {
      expectedRiskyJudgedSafe++;
      bucket.fn++;
    } else if (c.expected === "safe" && !judgedSafe) {
      expectedSafeJudgedRisky++;
      bucket.fp++;
    } else {
      bucket.correct++;
      if (c.expected === "risky") riskyScores.push(entry.score);
      else safeScores.push(entry.score);
    }
  }
  const totalCases = mainEntries.length;
  const correct = totalCases - expectedRiskyJudgedSafe - expectedSafeJudgedRisky - entries.filter((e) => e.phase === "main" && !e.checked).length;

  const mean = (arr: number[]): number => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);
  const riskyBelow60 = riskyScores.filter((s) => s < 60).length;

  const stabilityByCase = new Map<string, ScaleEntry[]>();
  for (const e of entries.filter((e) => e.phase === "stability" && e.checked && e.score !== null)) {
    const arr = stabilityByCase.get(e.case_id) ?? [];
    arr.push(e);
    stabilityByCase.set(e.case_id, arr);
  }
  let unanimousTier = 0;
  let majorityAgreement = 0;
  const stddevs: number[] = [];
  const spreads: number[] = [];
  for (const [, group] of stabilityByCase) {
    const scores = group.map((g) => g.score as number);
    const tiers = group.map((g) => g.tier ?? "");
    if (new Set(tiers).size === 1) unanimousTier++;
    const mu = mean(scores);
    const variance = mean(scores.map((s) => (s - mu) ** 2));
    stddevs.push(Math.sqrt(variance));
    spreads.push(Math.max(...scores) - Math.min(...scores));
    const risky = scores.filter((s) => s < 60).length;
    const decision = risky > stabilityRepeats / 2 ? "risky" : "safe";
    if (decision === (group[0]?.expected ?? "safe")) majorityAgreement++;
  }

  const jwsSampled = entries.filter((e) => e.jws_sample_verified !== null);
  return {
    run_id: runId,
    config: { perCategory, concurrency, stabilityCount, stabilityRepeats, seed, backend },
    totals: {
      calls: entries.length,
      errors,
      inputTokens,
      costUsd: (inputTokens * 0.042) / 1_000_000,
      latencyP50: p(0.5),
      latencyP95: p(0.95),
    },
    accuracy: {
      overall: totalCases > 0 ? correct / totalCases : 0,
      perCategory: perCategoryStats,
    },
    confusion: { expectedRiskyJudgedSafe, expectedSafeJudgedRisky },
    scoreSeparation: {
      riskyMean: mean(riskyScores),
      safeMean: mean(safeScores),
      riskyBelow60Rate: riskyScores.length ? riskyBelow60 / riskyScores.length : 0,
      safeAbove60Rate: safeScores.length ? safeScores.filter((s) => s >= 60).length / safeScores.length : 0,
    },
    stability: {
      cases: stabilityByCase.size,
      repeats: stabilityRepeats,
      unanimousTierRate: stabilityByCase.size ? unanimousTier / stabilityByCase.size : 0,
      meanScoreStddev: mean(stddevs),
      majorityDecisionAgreement: stabilityByCase.size ? majorityAgreement / stabilityByCase.size : 0,
      scoreSpreadP95: spreads.sort((a, b) => a - b)[Math.floor(0.95 * (spreads.length - 1))] ?? 0,
    },
    jwsSample: { sampled: jwsSampled.length, verified: jwsSampled.filter((e) => e.jws_sample_verified === true).length },
  };
}

function printReport(r: ScaleReport): void {
  console.log("\n== SCALE REPORT ==");
  console.log(`calls: ${r.totals.calls} | errors: ${r.totals.errors} | cost: $${r.totals.costUsd.toFixed(4)} | p50=${r.totals.latencyP50}ms p95=${r.totals.latencyP95}ms`);
  console.log(`accuracy: ${(r.accuracy.overall * 100).toFixed(1)}%`);
  console.log(`confusion: FN(expected risky→safe)=${r.confusion.expectedRiskyJudgedSafe} FP(expected safe→risky)=${r.confusion.expectedSafeJudgedRisky}`);
  console.log(`score separation: risky mean=${r.scoreSeparation.riskyMean.toFixed(1)} safe mean=${r.scoreSeparation.safeMean.toFixed(1)} | risky<60: ${(r.scoreSeparation.riskyBelow60Rate * 100).toFixed(0)}% safe>=60: ${(r.scoreSeparation.safeAbove60Rate * 100).toFixed(0)}%`);
  for (const [cat, s] of Object.entries(r.accuracy.perCategory).sort()) {
    console.log(`  ${cat.padEnd(14)} ${s.correct}/${s.n} (FN=${s.fn} FP=${s.fp})`);
  }
  console.log(`stability (${r.stability.cases}×${r.stability.repeats}): unanimous tier ${(r.stability.unanimousTierRate * 100).toFixed(0)}% | majority decision ${(r.stability.majorityDecisionAgreement * 100).toFixed(0)}% | mean stddev ${r.stability.meanScoreStddev.toFixed(1)} | spread p95 ${r.stability.scoreSpreadP95}`);
  console.log(`jws sample: ${r.jwsSample.verified}/${r.jwsSample.sampled} verified`);
  console.log(`report: ${EVAL_EVIDENCE_DIR}/scale-report.json | log: ${EVAL_EVIDENCE_DIR}/scale-log.jsonl`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

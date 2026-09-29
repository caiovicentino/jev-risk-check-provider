import { execSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient, QUESTION_SET_VERSION } from "../src/jev.js";
import { buildProvider, buildProductionLikeProvider, runCases, appendEntries, withLabelDerivedScreening, EVAL_EVIDENCE_DIR, SYNTHETIC_LOG, LIVE_LOG } from "./harness.js";
import { syntheticFixturesFor } from "./fixtures.js";
import { CASES } from "./cases.js";
import { generateCorpus, sampleForStability, type ScaleOptions } from "./scale-cases.js";
import type { ScaleEntry } from "./scale.js";
import { generateRedTeamCorpus } from "./redteam-cases.js";
import { aggregateRedteam, type RtEntry } from "./redteam.js";
import { benchBaseline, benchChatJudge, benchJev, sampleCases } from "./benchmark-judge.js";
import { evaluateGate } from "./gate.js";
import { runRealistic } from "./realistic.js";
import { runGrounded } from "./grounded.js";
import { wilson } from "./stats.js";

const args = process.argv.slice(2);
const has = (f: string): boolean => args.includes(f);
const PER_CATEGORY = has("--quick") ? 15 : 60;
const REDTEAM_COUNT = has("--quick") ? 300 : 1500;
const SKIP_BENCH = has("--no-benchmark");
const SKIP_GROUNDED = has("--no-grounded");

const typesafeKey = process.env.TYPESAFE_API_KEY;
const gatewayKey = process.env.AI_GATEWAY_API_KEY;
if (!typesafeKey && !gatewayKey) {
  console.error("eval:suite requires TYPESAFE_API_KEY or AI_GATEWAY_API_KEY");
  process.exit(1);
}

type SuiteLayer = {
  name: string;
  n: number;
  unchecked: number;
  accuracy: number;
  ci95: [number, number];
  fn: number;
  fp: number;
  costUsd: number;
  latencyP50: number;
  latencyP95: number;
  extra: string;
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

/** Unchecked (fail-closed) results are reported, never silently dropped from the denominator. */
function accuracyOf(entries: Array<{ checked: boolean; score: number | null; expected: string }>): { acc: number; ci: [number, number]; fn: number; fp: number; unchecked: number; n: number } {
  let fn = 0;
  let fp = 0;
  let n = 0;
  let unchecked = 0;
  for (const e of entries) {
    if (!e.checked || e.score === null) {
      unchecked++;
      continue;
    }
    n++;
    const safe = e.score >= 60;
    if (e.expected === "risky" && safe) fn++;
    if (e.expected === "safe" && !safe) fp++;
  }
  const w = wilson(n - fn - fp, n);
  return { acc: n > 0 ? (n - fn - fp) / n : 0, ci: [w.lo, w.hi], fn, fp, unchecked, n };
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const commit = execSync("git rev-parse --short HEAD 2>/dev/null || echo none", { encoding: "utf8" }).trim();
  const backendName = typesafeKey ? "typesafe-direct" : "vercel-ai-gateway";
  const backend = typesafeKey ? new JevClient({ apiKey: typesafeKey, baseUrl: process.env.TYPESAFE_BASE_URL }) : new GatewayJevClient();
  const provider = buildProductionLikeProvider(backend);
  const layers: SuiteLayer[] = [];
  let totalTokens = 0;
  const t0 = Date.now();
  const lat = (xs: number[]): [number, number] => {
    const s = [...xs].sort((a, b) => a - b);
    return [s[Math.floor(s.length / 2)] ?? 0, s[Math.floor(s.length * 0.95)] ?? 0];
  };

  console.log(`== EVAL SUITE == question-set: ${QUESTION_SET_VERSION} | backend: ${backendName} | commit: ${commit}`);
  console.log("regime: production (no caller screening; provider OFAC + threat feeds; on-chain off for synthetic addresses)");

  console.log("\n[1/8] synthetic (offline pipeline validation)");
  rmSync(SYNTHETIC_LOG, { force: true });
  const synEntries = await runCases(buildProvider(syntheticFixturesFor(CASES)), CASES);
  appendEntries(SYNTHETIC_LOG, synEntries, "synthetic");
  const syn = accuracyOf(synEntries);
  layers.push({ name: "synthetic", n: syn.n, unchecked: syn.unchecked, accuracy: syn.acc, ci95: syn.ci, fn: syn.fn, fp: syn.fp, costUsd: 0, latencyP50: 0, latencyP95: 0, extra: "mock model — plumbing only" });

  console.log("\n[2/8] shadow (live, production regime) → gate log");
  const shadowEntries = await runCases(provider, CASES);
  appendEntries(LIVE_LOG, shadowEntries, "live");
  totalTokens += shadowEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0);
  const shadow = accuracyOf(shadowEntries);
  const [s50, s95] = lat(shadowEntries.map((e) => e.latency_ms));
  const gate = evaluateGate(LIVE_LOG);
  layers.push({ name: "shadow (production regime)", n: shadow.n, unchecked: shadow.unchecked, accuracy: shadow.acc, ci95: shadow.ci, fn: shadow.fn, fp: shadow.fp, costUsd: (shadowEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0) * 0.042) / 1e6, latencyP50: s50, latencyP95: s95, extra: `review share ${pct(gate.reviewShare)} · gate ${gate.ready ? "READY" : "NOT READY"}` });

  console.log("\n[3/8] shadow (LEGACY label-derived screening — comparison only, not in the gate log)");
  const legacyEntries = await runCases(provider, withLabelDerivedScreening(CASES));
  totalTokens += legacyEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0);
  const legacy = accuracyOf(legacyEntries);
  const legacyReview = legacyEntries.filter((e) => e.tier === "medium" && (e.score ?? 0) >= 60).length / Math.max(1, legacy.n);
  layers.push({ name: "shadow (legacy label-leak sim)", n: legacy.n, unchecked: legacy.unchecked, accuracy: legacy.acc, ci95: legacy.ci, fn: legacy.fn, fp: legacy.fp, costUsd: 0, latencyP50: 0, latencyP95: 0, extra: `review share ${pct(legacyReview)} — label leaked into input; historical comparison only` });

  console.log(`\n[4/8] scale (${PER_CATEGORY * 7} described-scenario cases + stability)`);
  const corpus = generateCorpus({ perCategory: PER_CATEGORY, seed: 20260927 } as ScaleOptions);
  const scaleEntries: ScaleEntry[] = [];
  const runId = `suite-${Date.now()}`;
  await pool(corpus, 10, async (c) => {
    const ev = await provider.evaluate(c.request);
    scaleEntries.push({ run_id: runId, phase: "main", case_id: c.id, repeat: null, expected: c.expected, category: c.category, score: ev.result.score ?? null, tier: ev.result.tier ?? null, checked: ev.result.checked, latency_ms: ev.latencyMs, input_tokens: ev.usage?.inputTokens ?? null, error: ev.error, jws_sample_verified: null, ts: new Date().toISOString() });
  });
  const stabilityJobs = sampleForStability(corpus, 24, 20260928).flatMap((c) => [1, 2, 3, 4, 5].map((rep) => ({ c, rep })));
  await pool(stabilityJobs, 10, async ({ c, rep }) => {
    const ev = await provider.evaluate(c.request);
    scaleEntries.push({ run_id: runId, phase: "stability", case_id: c.id, repeat: rep, expected: c.expected, category: c.category, score: ev.result.score ?? null, tier: ev.result.tier ?? null, checked: ev.result.checked, latency_ms: ev.latencyMs, input_tokens: ev.usage?.inputTokens ?? null, error: ev.error, jws_sample_verified: null, ts: new Date().toISOString() });
  });
  totalTokens += scaleEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0);
  const scale = accuracyOf(scaleEntries.filter((e) => e.phase === "main"));
  const groups = new Map<string, ScaleEntry[]>();
  for (const e of scaleEntries.filter((x) => x.phase === "stability" && x.checked)) groups.set(e.case_id, [...(groups.get(e.case_id) ?? []), e]);
  const unanimous = [...groups.values()].filter((g) => new Set(g.map((x) => x.tier)).size === 1).length;
  const [c50, c95] = lat(scaleEntries.map((e) => e.latency_ms));
  layers.push({ name: "scale (described scenarios)", n: scale.n, unchecked: scale.unchecked, accuracy: scale.acc, ci95: scale.ci, fn: scale.fn, fp: scale.fp, costUsd: (scaleEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0) * 0.042) / 1e6, latencyP50: c50, latencyP95: c95, extra: `stability ${groups.size ? Math.round((unanimous / groups.size) * 100) : 0}% unanimous tier (24×5); contexts describe the risk` });

  console.log(`\n[5/8] red-team v6 corpus (${REDTEAM_COUNT} cases)`);
  const rtEntries: RtEntry[] = [];
  await pool(generateRedTeamCorpus(REDTEAM_COUNT, 73120260927), 12, async (c) => {
    const ev = await provider.evaluate(c.request);
    rtEntries.push({ case_id: c.id, family: c.family, strategy: c.strategy, expected: c.expected, score: ev.result.score ?? null, tier: ev.result.tier ?? null, checked: ev.result.checked, latency_ms: ev.latencyMs, input_tokens: ev.usage?.inputTokens ?? null, error: ev.error, context_preview: (c.request.context ?? "").slice(0, 120), ts: new Date().toISOString() });
  });
  totalTokens += rtEntries.reduce((a, e) => a + (e.input_tokens ?? 0), 0);
  const rt = aggregateRedteam(rtEntries);
  const rtAcc = accuracyOf(rtEntries.filter((e) => e.expected !== "ambiguous"));
  layers.push({ name: "red-team (v6 corpus)", n: rtAcc.n, unchecked: rtAcc.unchecked, accuracy: rtAcc.acc, ci95: rtAcc.ci, fn: rtAcc.fn, fp: rtAcc.fp, costUsd: rt.costUsd, latencyP50: rt.latencyP50, latencyP95: rt.latencyP95, extra: `dual-use prose claims held: ${rt.ambiguousClaims.n}` });

  console.log("\n[6/8] realistic (attacker-controlled context)");
  const realistic = await runRealistic(provider, has("--quick") ? 8 : 20);
  const realisticDetected = (variant: string) => {
    const g = realistic.rows.filter((r) => r.variant === variant && r.checked);
    return { hit: g.filter((r) => (r.score as number) < 60).length, n: g.length };
  };
  for (const variant of ["described", "attacker_benign", "no_context", "raw_agent_content"]) {
    const d = realisticDetected(variant);
    const w = wilson(d.hit, d.n);
    layers.push({ name: `realistic: ${variant}`, n: d.n, unchecked: realistic.rows.filter((r) => r.variant === variant && !r.checked).length, accuracy: w.p, ci95: [w.lo, w.hi], fn: d.n - d.hit, fp: 0, costUsd: 0, latencyP50: 0, latencyP95: 0, extra: "recall on risky cases (all risky)" });
  }

  let grounded: Record<string, unknown> | null = null;
  if (!SKIP_GROUNDED) {
    console.log("\n[7/8] grounded (external labels: OFAC, MetaMask, ScamSniffer, known-legit)");
    grounded = await runGrounded(backend);
    writeFileSync(`${EVAL_EVIDENCE_DIR}/grounded-report.json`, JSON.stringify(grounded, null, 2));
  }

  if (!SKIP_BENCH) {
    console.log("\n[8/8] benchmark vs chat judge (gpt-4.1-mini)");
    const sample = sampleCases();
    const baseline = await benchBaseline(sample);
    const chat = await benchChatJudge(sample);
    const jev = await benchJev(sample);
    const cw = wilson(Math.round(chat.accuracy * sample.length), sample.length);
    const jw = wilson(Math.round(jev.accuracy * sample.length), sample.length);
    layers.push({ name: "benchmark: chat judge", n: sample.length, unchecked: chat.errors, accuracy: chat.accuracy, ci95: [cw.lo, cw.hi], fn: chat.fn, fp: chat.fp, costUsd: chat.costUsd, latencyP50: chat.latencyP50, latencyP95: chat.latencyP95, extra: `keyword baseline ${pct(baseline.accuracy)}` });
    layers.push({ name: "benchmark: provider", n: sample.length, unchecked: jev.errors, accuracy: jev.accuracy, ci95: [jw.lo, jw.hi], fn: jev.fn, fp: jev.fp, costUsd: jev.costUsd, latencyP50: jev.latencyP50, latencyP95: jev.latencyP95, extra: "same described-scenario sample" });
  }

  const report = {
    timestamp: new Date().toISOString(),
    question_set: QUESTION_SET_VERSION,
    regime: "production (no caller screening; provider OFAC + feeds; on-chain off for synthetic addresses)",
    backend: backendName,
    commit,
    suite_cost_usd: (totalTokens * 0.042) / 1e6,
    suite_duration_ms: Date.now() - t0,
    layers,
    realistic: realistic.table,
    grounded: grounded?.layers ?? null,
    gate,
  };
  writeFileSync(`${EVAL_EVIDENCE_DIR}/consolidated-report.json`, JSON.stringify(report, null, 2));

  console.log("\n== CONSOLIDATED ==");
  console.log(`${"layer".padEnd(34)} ${"n".padStart(5)} ${"unchk".padStart(5)} ${"acc".padStart(7)} ${"95% CI".padStart(13)} ${"FN".padStart(4)} ${"FP".padStart(4)} ${"p50".padStart(6)}`);
  for (const l of layers) {
    console.log(`${l.name.padEnd(34)} ${String(l.n).padStart(5)} ${String(l.unchecked).padStart(5)} ${pct(l.accuracy).padStart(7)} ${`${pct(l.ci95[0])}–${pct(l.ci95[1])}`.padStart(13)} ${String(l.fn).padStart(4)} ${String(l.fp).padStart(4)} ${String(l.latencyP50).padStart(5)}ms  ${l.extra}`);
  }
  console.log("\nrealistic detection (risky cases, score < 60):");
  console.table(realistic.table);
  console.log(`gate (production regime): ${gate.ready ? "READY" : "NOT READY"} ${gate.failures.join("; ")}`);
  console.log(`report: ${EVAL_EVIDENCE_DIR}/consolidated-report.json | ${Math.round((Date.now() - t0) / 1000)}s | ~$${report.suite_cost_usd.toFixed(4)} model cost`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import type { JevLike } from "../src/jev.js";
import type { OnchainLookup } from "../src/onchain.js";
import type { ThreatIntelFeeds } from "../src/threat-intel.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import type { RiskCheckResult } from "../src/types.js";
import { CASES, type ShadowCase } from "./cases.js";

export const DECISION_THRESHOLD = 60;
export const EVAL_EVIDENCE_DIR = "eval/evidence";
export const LIVE_LOG = `${EVAL_EVIDENCE_DIR}/shadow-log.jsonl`;
export const SYNTHETIC_LOG = `${EVAL_EVIDENCE_DIR}/synthetic-log.jsonl`;

export type LogEntry = {
  case_id: string;
  expected: "safe" | "risky";
  category: string;
  verified: "real" | "fp" | null;
  score: number | null;
  tier: string | null;
  checked: boolean;
  latency_ms: number;
  input_tokens: number | null;
  output_tokens: number | null;
  error: string | null;
  mode: "live" | "synthetic";
  ts: string;
};

export type ProviderOptions = { onchain?: OnchainLookup | null; feeds?: ThreatIntelFeeds | null };

/** Bare provider (OFAC screen always on; no feeds, no on-chain) unless options say otherwise. */
export function buildProvider(jev: JevLike | null, opts: ProviderOptions = {}): Provider {
  const feeds = opts.feeds ?? null;
  return new Provider({
    host: "paysol.local",
    keyPair: generateKeyPair("jev-attest-v1"),
    jev,
    onchain: opts.onchain ?? null,
    ...(feeds ? { feeds: () => feeds } : {}),
  });
}

let diskFeeds: ThreatIntelFeeds | null = null;
/**
 * Production-regime provider for synthetic corpora: OFAC + embedded feeds (+ ScamSniffer
 * when cached locally), on-chain OFF — synthetic addresses have no chain history by
 * construction, so on-chain facts would only measure the corpus generator.
 */
export function buildProductionLikeProvider(jev: JevLike | null, opts: { onchain?: OnchainLookup | null } = {}): Provider {
  diskFeeds ??= loadFeedsFromDisk();
  return buildProvider(jev, { feeds: diskFeeds, onchain: opts.onchain ?? null });
}

/**
 * COMPARISON ONLY — reproduces the pre-v6 "screening-integrated simulation", which
 * derived the caller's screening field from the ground-truth label (risky → flagged,
 * safe → clean). That leaks the label into the input; never use it for the gate.
 */
export function withLabelDerivedScreening(cases: ShadowCase[]): ShadowCase[] {
  return cases.map((c) => ({
    ...c,
    request: { ...c.request, screening: { sanctions: c.expected === "safe" ? ("clean" as const) : ("flagged" as const) } },
  }));
}

export function decideFromScore(score: number | null, checked: boolean): "safe" | "risky" | "unchecked" {
  if (!checked || score === null) return "unchecked";
  return score >= DECISION_THRESHOLD ? "safe" : "risky";
}

export async function runCases(provider: Provider, cases: ShadowCase[]): Promise<LogEntry[]> {
  const entries: LogEntry[] = [];
  for (const c of cases) {
    const evaluation = await provider.evaluate(c.request);
    const r = evaluation.result;
    entries.push({
      case_id: c.id,
      expected: c.expected,
      category: c.category,
      verified: null,
      score: r.score ?? null,
      tier: r.tier ?? null,
      checked: r.checked,
      latency_ms: evaluation.latencyMs,
      input_tokens: evaluation.usage?.inputTokens ?? null,
      output_tokens: evaluation.usage?.outputTokens ?? null,
      error: evaluation.error,
      mode: "live",
      ts: new Date().toISOString(),
    });
  }
  return entries;
}

export function appendEntries(file: string, entries: LogEntry[], mode: "live" | "synthetic", carryLabels = true): void {
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  const priorLabels = carryLabels ? readLatestEntries(file) : new Map<string, LogEntry>();
  for (const e of entries) {
    const prior = priorLabels.get(e.case_id);
    const verified = prior?.verified != null ? prior.verified : e.verified;
    appendFileSync(file, `${JSON.stringify({ ...e, mode, verified })}\n`);
  }
}

export function readLatestEntries(file: string): Map<string, LogEntry> {
  const latest = new Map<string, LogEntry>();
  if (!existsSync(file)) return latest;
  for (const line of readFileSync(file, "utf8").split("\n").filter(Boolean)) {
    try {
      const entry = JSON.parse(line) as LogEntry;
      latest.set(entry.case_id, entry);
    } catch {
      continue;
    }
  }
  return latest;
}

export function upsertLabel(file: string, caseId: string, verified: "real" | "fp"): boolean {
  const latest = readLatestEntries(file);
  const entry = latest.get(caseId);
  if (!entry) return false;
  const updated: LogEntry = { ...entry, verified, ts: new Date().toISOString() };
  appendFileSync(file, `${JSON.stringify(updated)}\n`);
  return true;
}

export type PricedEvaluation = {
  inputTokens: number;
  costUsd: number;
};

export const JEVI_INPUT_USD_PER_MTOK = 0.042;

export function costFrom(tokens: number | null): number {
  if (tokens === null) return 0;
  return (tokens * JEVI_INPUT_USD_PER_MTOK) / 1_000_000;
}

export function resultFor(entry: LogEntry): RiskCheckResult {
  const base: RiskCheckResult = { checked: entry.checked };
  if (entry.score !== null) base.score = entry.score;
  if (entry.tier === "low" || entry.tier === "medium" || entry.tier === "high" || entry.tier === "critical") {
    base.tier = entry.tier;
  }
  return base;
}

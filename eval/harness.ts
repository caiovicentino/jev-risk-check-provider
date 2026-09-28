import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import type { JevLike } from "../src/jev.js";
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

export function buildProvider(jev: JevLike | null): Provider {
  return new Provider({ host: "paysol.local", keyPair: generateKeyPair("jev-attest-v1"), jev });
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

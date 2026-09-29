import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createPublicKey, verify as nodeVerify, type JsonWebKey } from "node:crypto";
import { CASES, type ShadowCase } from "./cases.js";
import { DECISION_THRESHOLD, EVAL_EVIDENCE_DIR } from "./harness.js";
import type { RiskCheckRequest, RiskCheckResult } from "../src/types.js";
import { buildPayFetch } from "./paid-fetch.js";

// X402CHECK_BASE points the suite at a staging target (e.g. `wrangler dev`) before a deploy.
const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const ENDPOINT = `${BASE}/v1/risk-check`;
const JWKS_URL = `${BASE}/.well-known/jwks.json`;
const EXPECTED_ISS = "did:web:x402check.xyz";
const DELAY_MS = 150;

type ProdLogEntry = {
  case_id: string;
  expected: "safe" | "risky";
  score: number | null;
  tier: string | null;
  checked: boolean;
  jws_valid: boolean | null;
  latency_ms: number;
  ts: string;
};

type ProdReport = {
  timestamp: string;
  endpoint: string;
  cases: number;
  correct: number;
  accuracy: number;
  jwsVerified: number;
  jwsMismatches: string[];
  perCategory: Record<string, { n: number; correct: number }>;
  notes: string[];
};

type AttestationClaims = {
  iss?: string;
  score?: number;
  tier?: string;
  exp?: number;
};

type JwsCheck = {
  ok: boolean;
  reason: string | null;
  claims: AttestationClaims | null;
};

type CaseOutcome = "correct" | "incorrect" | "unchecked" | "quota_exhausted";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJwks(): Promise<Map<string, JsonWebKey>> {
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error(`jwks fetch failed: HTTP ${res.status}`);
  const doc = (await res.json()) as { keys?: JsonWebKey[] };
  const keys = new Map<string, JsonWebKey>();
  for (const k of doc.keys ?? []) {
    if (k.kty === "EC" && typeof k.x === "string" && typeof k.y === "string") keys.set(typeof k.kid === "string" ? k.kid : "", k);
  }
  if (keys.size === 0) throw new Error("jwks fetch returned no usable EC keys");
  return keys;
}

function verifyAttestation(jws: string, keys: Map<string, JsonWebKey>): JwsCheck {
  const parts = jws.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed_jws", claims: null };
  const [headerB64, payloadB64, signatureB64] = parts;
  if (!headerB64 || !payloadB64 || !signatureB64) return { ok: false, reason: "malformed_jws", claims: null };
  let header: { alg?: string; kid?: string };
  let claims: AttestationClaims;
  try {
    header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")) as { alg?: string; kid?: string };
    claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as AttestationClaims;
  } catch {
    return { ok: false, reason: "undecodable_jws", claims: null };
  }
  if (header.alg !== "ES256") return { ok: false, reason: "unexpected_alg", claims };
  const jwk = header.kid ? keys.get(header.kid) : undefined;
  const key = jwk ?? (header.kid ? undefined : [...keys.values()][0]);
  if (!key) return { ok: false, reason: "unknown_kid", claims };
  let signatureValid: boolean;
  try {
    const publicKey = createPublicKey({ key, format: "jwk" });
    signatureValid = nodeVerify(
      "sha256",
      Buffer.from(`${headerB64}.${payloadB64}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureB64, "base64url"),
    );
  } catch {
    return { ok: false, reason: "verify_error", claims };
  }
  if (!signatureValid) return { ok: false, reason: "signature_invalid", claims };
  if (claims.iss !== EXPECTED_ISS) return { ok: false, reason: "iss_mismatch", claims };
  if (typeof claims.score !== "number" || typeof claims.tier !== "string") return { ok: false, reason: "missing_claims", claims };
  if (typeof claims.exp !== "number" || claims.exp <= Math.floor(Date.now() / 1000)) return { ok: false, reason: "expired", claims };
  return { ok: true, reason: null, claims };
}

let payFetch: ((input: string, init?: RequestInit) => Promise<Response>) | null = null;
// X402CHECK_CLIENT_IDS=a,b,c: install-style ids; on a free-tier 402 the run moves to the
// next id and retries the same case (each id: its own allowance, then the IP allowance).
const CLIENT_IDS = (process.env.X402CHECK_CLIENT_IDS ?? process.env.X402CHECK_CLIENT_ID ?? "").split(",").map((s) => s.trim()).filter(Boolean);
let clientIdx = 0;

async function postRiskCheck(req: RiskCheckRequest): Promise<{ status: number; body: RiskCheckResult | null }> {
  if (process.env.PAID && !payFetch) payFetch = await buildPayFetch();
  const doFetch = payFetch ?? fetch;
  const res = await doFetch(ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(process.env.PAID ? { "X-Risk-Check-Paid": "1" } : {}),
      // Optional install-style id: the free tier then charges this id first, then the IP allowance.
      ...(CLIENT_IDS[clientIdx] ? { "X-Risk-Check-Client": CLIENT_IDS[clientIdx] as string } : {}),
    },
    body: JSON.stringify(req),
    signal: AbortSignal.timeout(60_000),
  });
  let body: RiskCheckResult | null = null;
  try {
    body = (await res.json()) as RiskCheckResult;
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

async function runCase(c: ShadowCase, keys: Map<string, JsonWebKey>, bucket: { n: number; correct: number }): Promise<{ entry: ProdLogEntry; outcome: CaseOutcome; detail: string; mismatch: string | null }> {
  const t0 = Date.now();
  const base = { case_id: c.id, expected: c.expected };
  try {
    const { status, body } = await postRiskCheck(c.request);
    const latency = Date.now() - t0;
    const ts = new Date().toISOString();
    if (status === 402) {
      return {
        entry: { ...base, score: null, tier: null, checked: false, jws_valid: null, latency_ms: latency, ts },
        outcome: "quota_exhausted",
        detail: "HTTP 402 payment_required — free quota exhausted",
        mismatch: null,
      };
    }
    if (status !== 200 || !body) {
      return {
        entry: { ...base, score: null, tier: null, checked: false, jws_valid: null, latency_ms: latency, ts },
        outcome: "unchecked",
        detail: `HTTP ${status} — not counted`,
        mismatch: null,
      };
    }
    if (!body.checked) {
      return {
        entry: { ...base, score: null, tier: null, checked: false, jws_valid: null, latency_ms: latency, ts },
        outcome: "unchecked",
        detail: "checked=false (JEV error) — not counted",
        mismatch: null,
      };
    }
    const score = body.score ?? null;
    const tier = body.tier ?? null;
    let jwsValid: boolean | null = null;
    let mismatch: string | null = null;
    if (body.jws) {
      const check = verifyAttestation(body.jws, keys);
      if (!check.ok) {
        jwsValid = false;
        mismatch = `${c.id}: ${check.reason}`;
      } else if (check.claims && (check.claims.score !== body.score || check.claims.tier !== body.tier)) {
        jwsValid = false;
        mismatch = `${c.id}: claims mismatch (jws score=${check.claims.score}/${check.claims.tier} vs response score=${body.score}/${body.tier})`;
      } else {
        jwsValid = true;
      }
    }
    const decision = score !== null && score >= DECISION_THRESHOLD ? "safe" : "risky";
    const isCorrect = decision === c.expected;
    if (isCorrect) bucket.correct++;
    return {
      entry: { ...base, score, tier, checked: true, jws_valid: jwsValid, latency_ms: latency, ts },
      outcome: isCorrect ? "correct" : "incorrect",
      detail: `${decision} (score=${score}, tier=${tier ?? "-"})`,
      mismatch,
    };
  } catch (err) {
    const latency = Date.now() - t0;
    return {
      entry: { ...base, score: null, tier: null, checked: false, jws_valid: null, latency_ms: latency, ts: new Date().toISOString() },
      outcome: "unchecked",
      detail: `request error: ${String(err)}`,
      mismatch: null,
    };
  }
}

function printReport(r: ProdReport, attempted: number, quotaExhausted: boolean): void {
  console.log("\n== PROD REPORT ==");
  console.log(`endpoint: ${r.endpoint}`);
  console.log(`cases: ${r.cases} | attempted: ${attempted} | correct: ${r.correct} | accuracy: ${(r.accuracy * 100).toFixed(1)}%`);
  console.log(`jws verified: ${r.jwsVerified} | mismatches: ${r.jwsMismatches.length}`);
  for (const [cat, s] of Object.entries(r.perCategory).sort()) {
    console.log(`  ${cat.padEnd(14)} ${String(s.correct).padStart(2, "0")}/${s.n}`);
  }
  for (const n of r.notes) console.log(`note: ${n}`);
  if (quotaExhausted) console.log("STOPPED: free quota exhausted (402) — rerun later for full coverage");
  console.log(`report: ${EVAL_EVIDENCE_DIR}/prod-report.json | log: ${EVAL_EVIDENCE_DIR}/prod-log.jsonl`);
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  console.log(`prod eval: ${CASES.length} authored cases against ${ENDPOINT}`);
  const keys = await fetchJwks();
  console.log(`jwks: ${keys.size} key(s) fetched from ${JWKS_URL}`);
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  const logFile = `${EVAL_EVIDENCE_DIR}/prod-log.jsonl`;
  const notes: string[] = [];
  const jwsMismatches: string[] = [];
  const perCategory: Record<string, { n: number; correct: number }> = {};
  const entries: ProdLogEntry[] = [];
  let correct = 0;
  let jwsVerified = 0;
  let quotaExhausted = false;

  for (let i = 0; i < CASES.length; i++) {
    const c = CASES[i]!;
    const bucket = (perCategory[c.category] ??= { n: 0, correct: 0 });
    bucket.n++;
    let run = await runCase(c, keys, bucket);
    while (run.outcome === "quota_exhausted" && !process.env.PAID && clientIdx + 1 < CLIENT_IDS.length) {
      clientIdx++;
      console.log(`  free allowance exhausted — switching to client id #${clientIdx + 1}`);
      run = await runCase(c, keys, bucket);
    }
    const { entry, outcome, detail, mismatch } = run;
    entries.push(entry);
    appendFileSync(logFile, `${JSON.stringify(entry)}\n`);
    if (mismatch) jwsMismatches.push(mismatch);
    if (outcome === "correct") correct++;
    if (entry.jws_valid === true) jwsVerified++;
    const mark = outcome === "correct" ? "PASS" : outcome === "incorrect" ? "MISS" : "SKIP";
    console.log(`  [${String(entries.length).padStart(2, "0")}/${CASES.length}] ${c.id}: ${mark} — ${detail}`);
    if (outcome === "quota_exhausted") {
      quotaExhausted = true;
      notes.push(`${c.id}: ${detail} — stopped without retry, ${CASES.length - entries.length} cases not run`);
      break;
    }
    if (outcome === "unchecked") notes.push(`${c.id}: ${detail}`);
    if (i < CASES.length - 1) await sleep(DELAY_MS);
  }

  const report: ProdReport = {
    timestamp: startedAt,
    endpoint: ENDPOINT,
    cases: CASES.length,
    correct,
    accuracy: correct / CASES.length,
    jwsVerified,
    jwsMismatches,
    perCategory,
    notes,
  };
  writeFileSync(`${EVAL_EVIDENCE_DIR}/prod-report.json`, JSON.stringify(report, null, 2));
  printReport(report, entries.length, quotaExhausted);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

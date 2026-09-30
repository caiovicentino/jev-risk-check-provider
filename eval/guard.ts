// Proof for the signing guard (@x402check/client/guard): would it have refused to sign real
// drainer transactions, and signed real legitimate ones?
//
// Cases: the exact transactions of eval/simulation.ts's last run (its report's `sample`):
// - REAL transactions that victims sent to ScamSniffer-listed drainer contracts on Ethereum;
// - REAL recent transactions to well-known contracts (routers, lending, WETH, Lido, Seaport,
//   USDC and USDT transfers).
// Each one is re-fetched by hash and handed to the guard as the signature request an agent's
// account would make. The guard decodes it (the counterparty inside the calldata), checks it
// against the REAL provider in process, verifies the ES256 attestation and its binding to
// the request, and decides.
//
// What the provider runs:
// - simulation on public mainnet RPCs, at the latest block;
// - OFAC, the MetaMask list, Forta code fingerprints, on-chain facts, contract verification;
// - a neutral model: no content to read, so the model adds nothing.
// The ScamSniffer feed is OFF: the drainer contracts come from it, so a hit would be circular.
//
//   npx tsx eval/guard.ts [--concurrency 4]
//
// No money moves: nothing is signed or sent. The model makes no calls.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createGuard, type GuardVerdict } from "../packages/client/src/guard.js";
import { jwkThumbprint } from "../packages/client/src/verify.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { createSimulator } from "../src/simulation.js";
import { createContractIntel } from "../src/contract-intel.js";
import { createOnchainLookup } from "../src/onchain.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import type { Answer } from "../src/types.js";
import { numberFlag } from "./flags.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { redactScamSniffer, scamSnifferOnly } from "./redact.js";
import { wilson } from "./stats.js";

const BS = "https://eth.blockscout.com/api/v2";
const CONCURRENCY = numberFlag("concurrency", 4);
const NEUTRAL: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};

type SampleRow = { label: "drainer" | "legit"; tx: string; status: string; flagged: boolean };
type Row = SampleRow & {
  fetched: boolean;
  action: string | null;
  code: string | null;
  counterparty: string | null;
  interaction: string | null;
  tier: string | null;
  score: number | null;
  categories: string[];
  simulation: string | null;
  findings: string[];
  reason: string | null;
};
const EMPTY = { action: null, code: null, counterparty: null, interaction: null, tier: null, score: null, categories: [] as string[], simulation: null, findings: [] as string[], reason: null };
type Tx = { from: string; to: string; value: string; input: string };

async function fetchTx(hash: string): Promise<Tx | null> {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await fetch(`${BS}/transactions/${hash}`, { headers: { accept: "application/json", "user-agent": "x402check-eval/guard" }, signal: AbortSignal.timeout(20000) });
      if (res.status === 429) {
        await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      if (!res.ok) return null;
      const t = (await res.json()) as { from?: { hash: string }; to?: { hash: string } | null; value?: string; raw_input?: string };
      if (!t.from || !t.to) return null;
      return { from: t.from.hash, to: t.to.hash, value: t.value ?? "0", input: t.raw_input ?? "0x" };
    } catch {
      await new Promise((r) => setTimeout(r, 800));
    }
  }
  return null;
}

async function pool<T, R>(items: T[], n: number, fn: (x: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k] as T, k);
    }
  }));
  return out;
}

async function main(): Promise<void> {
  const sim = JSON.parse(readFileSync(new URL("./evidence/simulation-report.json", import.meta.url), "utf8")) as { timestamp: string; sample: SampleRow[] };
  const contractIntel = createContractIntel({ timeoutMs: 8000 });
  // The in-process provider signs with its own key: the guard pins that key (as it pins
  // production's), so verification runs exactly as in production.
  const keyPair = generateKeyPair("jev-attest-v1");
  const provider = new Provider({
    host: "x402check.xyz",
    keyPair,
    jev: { systemOne: async () => ({ answers: NEUTRAL, usage: { inputTokens: 0, outputTokens: 0 } }) },
    onchain: createOnchainLookup({ timeoutMs: 4000 }),
    feeds: (() => {
      const feeds = loadFeedsFromDisk({ scamsniffer: false });
      return () => feeds;
    })(),
    simulator: createSimulator({ timeoutMs: 8000, contractIntel }),
    contractIntel,
  });
  const handler = createHandler({ provider });
  const inProcess = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string }) =>
    handler(new Request(url, { method: init?.method ?? "GET", headers: init?.headers ?? {}, ...(init?.body !== undefined ? { body: init.body } : {}) }));
  const guard = createGuard({ fetch: inProcess as never, timeoutMs: 60_000, pinnedKeys: [await jwkThumbprint(keyPair.publicJwk)] });

  const started = Date.now();
  const rows: Row[] = await pool(sim.sample, CONCURRENCY, async (s, i): Promise<Row> => {
    const tx = await fetchTx(s.tx);
    if (!tx) return { ...s, ...EMPTY, fetched: false };
    let verdict: GuardVerdict;
    try {
      verdict = await guard.check({ kind: "transaction", from: tx.from, transaction: { to: tx.to, value: tx.value, data: tx.input, chainId: 1 } });
    } catch (err) {
      return { ...s, ...EMPTY, fetched: true, action: "not_verified", code: `guard_error: ${String(err).slice(0, 80)}` };
    }
    const first = verdict.checks[0];
    const result = first?.result as { tier?: string; score?: number; categories?: string[]; evidence?: { simulation?: { status?: string; findings?: string[] } } } | undefined;
    if ((i + 1) % 25 === 0) console.log(`${i + 1}/${sim.sample.length} (${Math.round((Date.now() - started) / 1000)} s)`);
    return {
      ...s,
      fetched: true,
      action: verdict.action,
      code: verdict.code ?? null,
      counterparty: first?.request.wallet ?? null,
      interaction: first?.request.interaction?.type ?? null,
      tier: result?.tier ?? null,
      score: result?.score ?? null,
      categories: result?.categories ?? [],
      simulation: result?.evidence?.simulation?.status ?? null,
      findings: result?.evidence?.simulation?.findings ?? [],
      reason: verdict.reasons[0]?.slice(0, 160) ?? null,
    };
  });

  const summarize = (label: "drainer" | "legit") => {
    const g = rows.filter((r) => r.label === label && r.fetched);
    const done = g.filter((r) => r.action !== "not_verified");
    const by = (a: string) => g.filter((r) => r.action === a).length;
    const refused = done.filter((r) => r.action !== "allow").length;
    // The simulation eval's population: simulated OK at its run (the rest reverted or were unavailable then).
    const simulatedOk = g.filter((r) => r.status === "ok");
    const simDone = simulatedOk.filter((r) => r.action !== "not_verified");
    const simRefused = simDone.filter((r) => (r.action === "block" || r.action === "warn")).length;
    const simBlocked = simDone.filter((r) => r.action === "block").length;
    const w = wilson(simBlocked, simDone.length);
    return {
      transactions: g.length,
      verdicts: { allow: by("allow"), warn: by("warn"), block: by("block"), not_verified: by("not_verified") },
      refused_for_an_autonomous_agent: `${refused}/${done.length}`,
      among_simulated_ok_in_the_simulation_eval: {
        transactions: simulatedOk.length,
        blocked: `${simBlocked}/${simDone.length}`,
        blocked_rate: `${(w.p * 100).toFixed(1)}% (95% CI ${(w.lo * 100).toFixed(1)}–${(w.hi * 100).toFixed(1)}%)`,
        blocked_or_warned: `${simRefused}/${simDone.length}`,
      },
      [label === "legit" ? "refusals" : "signed"]: g
        .filter((r) => (label === "legit" ? r.action === "block" || r.action === "warn" : r.action === "allow"))
        .map((r) => ({ tx: r.tx, action: r.action, counterparty: r.counterparty, categories: r.categories, simulation: r.simulation, findings: r.findings })),
    };
  };
  const report = {
    timestamp: new Date().toISOString(),
    cases_from: `eval/evidence/simulation-report.json (${sim.timestamp})`,
    provider: "in process, same code as production; ScamSniffer feed OFF (circular); neutral model; simulation on public mainnet RPCs at the latest block",
    duration_s: Math.round((Date.now() - started) / 1000),
    fetched: rows.filter((r) => r.fetched).length,
    drainer: summarize("drainer"),
    legit: summarize("legit"),
    rows: rows.map((r) => (r.fetched ? { label: r.label, tx: r.tx, action: r.action, code: r.code, counterparty: r.counterparty, tier: r.tier, score: r.score, categories: r.categories, simulation: r.simulation, findings: r.findings } : { label: r.label, tx: r.tx, fetched: false })),
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  // ScamSniffer-only entries (GPL) are written as hashes: the report is committed.
  writeFileSync(`${EVAL_EVIDENCE_DIR}/guard-report.json`, JSON.stringify(redactScamSniffer(report, await scamSnifferOnly()), null, 2));
  console.log(JSON.stringify({ drainer: report.drainer.verdicts, drainer_sim_ok: report.drainer.among_simulated_ok_in_the_simulation_eval, legit: report.legit.verdicts, legit_sim_ok: report.legit.among_simulated_ok_in_the_simulation_eval }, null, 1));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

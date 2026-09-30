// What x402check_pay would decide for REAL x402 merchants: a random sample of payees listed in
// the Coinbase x402 Bazaar (the public discovery catalog), each checked against PRODUCTION
// exactly as the tool checks a payment right before signing it (the payee, network, asset,
// amount and the resource's site). Nothing is paid to anyone: only the checks are bought, from
// prepaid credits ($0.001 each).
//
//   npx tsx eval/pay-guard.ts [--n 25] [--seed 402]
//
// Listed merchants are not known to be benign, so this is not a false-positive rate in the
// strict sense: it is how often an autonomous agent using x402check_pay would be stopped on the
// catalog's merchants, and why. Credits: ~/.config/paysol/x402check-credit-token (never printed;
// the report carries a SHA-256 prefix).
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { createClient } from "../packages/client/src/client.js";
import { createGuard, X402CHECK_PAY_TO } from "../packages/client/src/guard.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { wilson } from "./stats.js";
import { numberFlag } from "./flags.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const DISCOVERY = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const arg = (name: string, fallback: number) => numberFlag(name, fallback);
const N = arg("n", 25);
const SEED = arg("seed", 402);

type Listed = { resource: string; accepts?: Array<{ scheme?: string; network?: string; amount?: string | null; maxAmountRequired?: string | null; asset?: string; payTo?: string }> };
type Candidate = { resource: string; payTo: string; amount: string };
type Row = {
  host: string;
  pay_to: string;
  amount_usd: number;
  action: string;
  code: string | null;
  tier: string | null;
  score: number | null;
  categories: string[];
  payee: { contract: boolean | null; activity: string | null; tx_count: number | null } | null;
  reason: string | null;
  ms: number;
};

/** Deterministic PRNG (mulberry32): the same seed draws the same sample from the same catalog. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function page(offset: number): Promise<{ items: Listed[]; total: number }> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`${DISCOVERY}?limit=100&offset=${offset}`, { signal: AbortSignal.timeout(30_000) }).catch(() => null);
    if (res?.ok) {
      const body = (await res.json()) as { items?: Listed[]; pagination?: { total?: number } };
      return { items: body.items ?? [], total: body.pagination?.total ?? 0 };
    }
    await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  throw new Error(`the catalog page at offset ${offset} could not be read`);
}

async function main(): Promise<void> {
  const random = rng(SEED);
  const { total } = await page(0);
  const byPayee = new Map<string, Candidate>();
  const offsets = new Set<number>();
  while (byPayee.size < N * 3 && offsets.size < 60) {
    const offset = Math.floor(random() * Math.max(1, total - 100));
    if (offsets.has(offset)) continue;
    offsets.add(offset);
    for (const item of (await page(offset)).items) {
      const a = (item.accepts ?? []).find((x) => x.scheme === "exact" && x.network === "eip155:8453" && x.asset?.toLowerCase() === USDC_BASE);
      const amount = a?.amount ?? a?.maxAmountRequired;
      if (!a?.payTo || !/^0x[0-9a-fA-F]{40}$/.test(a.payTo) || !amount || !/^\d{1,78}$/.test(amount)) continue;
      if (X402CHECK_PAY_TO.some((t) => t.toLowerCase() === a.payTo!.toLowerCase())) continue;
      let url: URL;
      try {
        url = new URL(item.resource);
      } catch {
        continue;
      }
      if (url.protocol !== "https:") continue;
      const key = a.payTo.toLowerCase();
      if (!byPayee.has(key)) byPayee.set(key, { resource: `${url.origin}${url.pathname}`.slice(0, 512), payTo: a.payTo, amount });
    }
  }
  const pool = [...byPayee.values()];
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [pool[i], pool[j]] = [pool[j] as Candidate, pool[i] as Candidate];
  }
  const sample = pool.slice(0, N);
  console.log(`catalog: ${total} resources · ${offsets.size} pages read · ${byPayee.size} distinct Base USDC payees · sample ${sample.length}`);

  const token = readFileSync(`${homedir()}/.config/paysol/x402check-credit-token`, "utf8").trim();
  const guard = createGuard({ baseUrl: BASE, creditToken: token, timeoutMs: 30_000 });
  const balance = async () => (await createClient({ baseUrl: BASE, creditToken: token }).creditBalance()).balanceUsd;
  const before = await balance();
  const rows: Row[] = [];
  for (const c of sample) {
    const t0 = Date.now();
    const v = await guard.check({ kind: "x402_payment", payTo: c.payTo, network: "eip155:8453", amount: c.amount, asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", resource: c.resource });
    const check = v.checks[0];
    const result = check?.result as { tier?: string; score?: number; categories?: string[]; evidence?: { onchain?: { is_contract?: boolean; activity?: string; tx_count?: number }; domain?: { impersonation?: string } } } | undefined;
    const row: Row = {
      host: new URL(c.resource).host,
      pay_to: c.payTo,
      amount_usd: Number(c.amount) / 1e6,
      action: v.action,
      code: v.code ?? null,
      tier: result?.tier ?? null,
      score: result?.score ?? null,
      categories: result?.categories ?? [],
      payee: result?.evidence?.onchain ? { contract: result.evidence.onchain.is_contract ?? null, activity: result.evidence.onchain.activity ?? null, tx_count: result.evidence.onchain.tx_count ?? null } : null,
      reason: v.reasons[0]?.slice(0, 160) ?? null,
      ms: Date.now() - t0,
    };
    rows.push(row);
    console.log(`${row.action.padEnd(12)} ${row.host.padEnd(36)} ${row.pay_to.slice(0, 10)}… ${row.tier ?? "-"} ${row.score ?? "-"} ${row.categories.join(",")} (${row.ms} ms)`);
  }
  const after = await balance();
  const count = (a: string) => rows.filter((r) => r.action === a).length;
  const decided = rows.filter((r) => r.action !== "not_verified");
  const allowed = wilson(count("allow"), decided.length);
  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    catalog: { source: DISCOVERY, total_resources: total, pages_read: offsets.size, distinct_base_usdc_payees: byPayee.size, seed: SEED },
    method: "each payee checked as x402check_pay checks a payment right before signing it: payee, eip155:8453, USDC, the listed amount, the resource's site; attestation verified and bound (createGuard.check, kind x402_payment). Nothing was paid.",
    credit_token: `sha256:${createHash("sha256").update(token).digest("hex").slice(0, 12)}`,
    balance_before: before,
    balance_after: after,
    verdicts: { allow: count("allow"), warn: count("warn"), block: count("block"), not_verified: count("not_verified") },
    allowed_rate: `${(allowed.p * 100).toFixed(1)}% (95% CI ${(allowed.lo * 100).toFixed(1)}–${(allowed.hi * 100).toFixed(1)}%) of ${decided.length} decided`,
    rows,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/pay-guard-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ verdicts: report.verdicts, allowed_rate: report.allowed_rate, balance_before: before, balance_after: after }));
}

main().catch((err) => {
  console.error(String(err).slice(0, 300));
  process.exit(1);
});

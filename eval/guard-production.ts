// The signing guard against PRODUCTION (https://x402check.xyz), paid from prepaid credits.
//
// It takes a few transactions from the last `eval/guard.ts` run: drainers the in-process
// guard blocked, and legitimate ones it allowed. It re-fetches them, and asks the production
// guard path to decide. Nothing is signed or sent.
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/guard-production.ts [--each 2]
//
// Credits: ~/.config/paysol/x402check-credit-token (mode 600). When it is missing, a $0.10 pack
// is bought with the probe payer (eval/paid-fetch.ts), to our own pay_to. The token is never
// printed; the report carries a SHA-256 prefix. Each simulated check costs $0.005.
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { createClient } from "../packages/client/src/client.js";
import { createGuard } from "../packages/client/src/guard.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch } from "./paid-fetch.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const EACH = Number(process.argv[process.argv.indexOf("--each") + 1] || 2);
const TOKEN_FILE = `${homedir()}/.config/paysol/x402check-credit-token`;
const BS = "https://eth.blockscout.com/api/v2";

async function creditToken(): Promise<{ token: string; bought: boolean }> {
  if (existsSync(TOKEN_FILE)) return { token: readFileSync(TOKEN_FILE, "utf8").trim(), bought: false };
  const pay = await buildPayFetch();
  const client = createClient({ baseUrl: BASE, fetch: pay as never, timeoutMs: 60_000 });
  const purchase = await client.buyCredits(0.1);
  if (!purchase.token) throw new Error("the purchase returned no token");
  mkdirSync(`${homedir()}/.config/paysol`, { recursive: true });
  writeFileSync(TOKEN_FILE, purchase.token, { mode: 0o600 });
  chmodSync(TOKEN_FILE, 0o600);
  return { token: purchase.token, bought: true };
}

async function fetchTx(hash: string): Promise<{ from: string; to: string; value: string; input: string } | null> {
  const res = await fetch(`${BS}/transactions/${hash}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(20000) });
  if (!res.ok) return null;
  const t = (await res.json()) as { from?: { hash: string }; to?: { hash: string } | null; value?: string; raw_input?: string };
  return t.from && t.to ? { from: t.from.hash, to: t.to.hash, value: t.value ?? "0", input: t.raw_input ?? "0x" } : null;
}

async function main(): Promise<void> {
  const local = JSON.parse(readFileSync(new URL("./evidence/guard-report.json", import.meta.url), "utf8")) as { rows: Array<{ label: string; tx: string; action?: string }> };
  const picks = [
    ...local.rows.filter((r) => r.label === "drainer" && r.action === "block").slice(0, EACH),
    ...local.rows.filter((r) => r.label === "legit" && r.action === "allow").slice(0, EACH),
  ];
  const { token, bought } = await creditToken();
  const guard = createGuard({ baseUrl: BASE, creditToken: token, timeoutMs: 30_000 });
  const balance = async () => (await createClient({ baseUrl: BASE, creditToken: token }).creditBalance()).balanceUsd;
  const before = await balance();
  const rows = [];
  for (const p of picks) {
    const tx = await fetchTx(p.tx);
    if (!tx) {
      rows.push({ label: p.label, tx: p.tx, in_process: p.action, production: "tx_unavailable" });
      continue;
    }
    const t0 = Date.now();
    const v = await guard.check({ kind: "transaction", from: tx.from, transaction: { to: tx.to, value: tx.value, data: tx.input, chainId: 1 } });
    const first = v.checks[0]?.result as { tier?: string; categories?: string[] } | undefined;
    rows.push({ label: p.label, tx: p.tx, in_process: p.action, production: v.action, same: v.action === p.action, ms: Date.now() - t0, tier: first?.tier ?? null, categories: first?.categories ?? [], reason: v.reasons[0]?.slice(0, 140) ?? null });
    console.log(`${p.label} ${p.tx.slice(0, 12)}… in-process=${p.action} production=${v.action} (${Date.now() - t0} ms) ${first?.categories?.join(",") ?? ""}`);
  }
  const after = await balance();
  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    credit_token: `sha256:${createHash("sha256").update(token).digest("hex").slice(0, 12)}`,
    pack_bought_now: bought,
    balance_before: before,
    balance_after: after,
    rows,
    agreement: `${rows.filter((r) => "same" in r && r.same).length}/${rows.length}`,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/guard-production-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ agreement: report.agreement, balance_before: before, balance_after: after }));
}

main().catch((err) => {
  console.error(String(err).slice(0, 300));
  process.exit(1);
});

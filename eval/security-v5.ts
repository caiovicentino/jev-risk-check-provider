// Live probes for v0.5: per-network prices, facilitator routing by compatibility and cost
// (margins in /status), prepaid credits (buy once via x402, then checks with no payment
// round trip), and (v0.5.1) which facilitator actually settled: each settlement's sender on
// Base is matched against the facilitators' published signers.
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/security-v5.ts
//
// Budget: one per-call check on Base ($0.0035) and one $0.10 credit pack, through
// eval/paid-fetch.ts. Without a funded payer the paid probes are SKIP, never PASS. The credit
// token is a secret: the report carries only a SHA-256 prefix of it.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt, type PayFetch, type SettlementReceipt } from "./paid-fetch.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const USER = "0x1111111111111111111111111111111111111111";
const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
/** The published price table (deploy/pricing.ts). */
const EXPECTED: Record<string, string> = { "eip155:8453": "0.0035", "eip155:137": "0.007", "eip155:42161": "0.009", "eip155:43114": "0.001", "eip155:143": "0.001", "eip155:1329": "0.002", [SOL]: "0.002" };

const receipts: Array<SettlementReceipt & { probe: string }> = [];
type Res = { status: number; headers: Headers; json: Record<string, unknown> | null; ms: number };
type Outcome = { id: string; status: "PASS" | "FAIL" | "SKIP"; detail: string };

let payFetch: PayFetch | null | undefined;
async function call(method: string, path: string, body?: unknown, opts: { paid?: boolean; headers?: Record<string, string> } = {}): Promise<Res> {
  if (opts.paid && payFetch === undefined) payFetch = await buildPayFetch().catch(() => null);
  if (opts.paid && !payFetch) return { status: 0, headers: new Headers(), json: { error: "no payer configured (~/.config/paysol)" }, ms: 0 };
  const t = Date.now();
  const res = await ((opts.paid ? payFetch : null) ?? fetch)(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(opts.headers ?? {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await res.text();
  const ms = Date.now() - t;
  const receipt = opts.paid ? settlementReceipt(res.headers) : null;
  if (receipt) receipts.push({ probe: `${method} ${path}`, ...receipt });
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json, ms };
}

function challenge(res: Res): Array<{ network: string; amount: string; extra?: Record<string, unknown> }> {
  const h = res.headers.get("payment-required");
  if (!h) return [];
  return (JSON.parse(Buffer.from(h, "base64").toString("utf8")) as { accepts: Array<{ network: string; amount: string; extra?: Record<string, unknown> }> }).accepts;
}

async function main(): Promise<void> {
  const out: Outcome[] = [];
  const add = (id: string, pass: boolean | null, detail: string) => {
    out.push({ id, status: pass === null ? "SKIP" : pass ? "PASS" : "FAIL", detail });
    console.log(`${pass === null ? "SKIP" : pass ? "PASS" : "FAIL"}  ${id} — ${detail}`);
  };
  const micro = (usd: string) => String(Math.round(Number(usd) * 1e6));

  const disc = (await call("GET", "/.well-known/risk-check.json")).json as { version?: string; pricing?: { amount?: string; amounts_by_network?: Record<string, string>; credits?: Record<string, string> } } | null;
  const table = disc?.pricing?.amounts_by_network ?? {};
  add(
    "discovery_prices_and_credits",
    String(disc?.version).startsWith("0.5.") && JSON.stringify(table) === JSON.stringify(EXPECTED) && disc?.pricing?.amount === "0.0035" && disc?.pricing?.credits?.check_usd === "0.001" && disc?.pricing?.credits?.simulated_check_usd === "0.005",
    `version=${disc?.version} amount=${disc?.pricing?.amount} by_network=${JSON.stringify(table)} credits=${JSON.stringify(disc?.pricing?.credits)}`,
  );

  const unpaid = await call("POST", "/v1/risk-check", { wallet: WALLET, chain: "base" });
  const accepts = challenge(unpaid);
  const wrong = accepts.filter((a) => a.amount !== micro(EXPECTED[a.network] ?? "NaN")).map((a) => `${a.network}=${a.amount}`);
  const base = accepts.find((a) => a.network === "eip155:8453");
  const sol = accepts.find((a) => a.network === SOL);
  add(
    "challenge_per_network_prices",
    unpaid.status === 402 && accepts.length === 7 && wrong.length === 0 && base?.extra?.assetTransferMethod !== "permit2" && String(sol?.extra?.feePayer ?? "").startsWith("DeXter"),
    `${accepts.length} options; mismatches=${JSON.stringify(wrong)}; Base transfer=${String(base?.extra?.assetTransferMethod ?? "eip3009")} (any wallet can pay); Solana fee payer=${String(sol?.extra?.feePayer ?? "").slice(0, 10)}…`,
  );

  const st = (await call("GET", "/status")).json as {
    payments?: Array<{ network: string; facilitator: string | null; transfer_method: string | null; fee_usd: number | null; margin_usd: number | null; margin_pct: number | null; below_floor: boolean }>;
    facilitators?: Array<{ name: string; ok: boolean; networks: string[]; error?: string }>;
  } | null;
  const routes = Array.isArray(st?.payments) ? st.payments : [];
  const r = Object.fromEntries(routes.map((x) => [x.network, x]));
  const baseRoute = r["eip155:8453"]?.facilitator ?? null;
  add(
    "status_routes_and_margins",
    routes.length === 7 && (baseRoute === "payai" || baseRoute === "cdp") && r["eip155:8453"]?.transfer_method === "eip3009" && r[SOL]?.facilitator === "dexter" && routes.every((x) => !x.below_floor && (x.margin_usd === null || x.margin_usd > 0)),
    routes.map((x) => `${x.network.replace("eip155:", "")}:${x.facilitator}/${x.transfer_method} fee=${x.fee_usd} margin=${x.margin_pct}%`).join(" · "),
  );
  const facs = Array.isArray(st?.facilitators) ? st.facilitators : [];
  const cdp = facs.find((f) => f.name === "cdp");
  add(
    "status_facilitators",
    facs.length >= 2 && facs.every((f) => f.ok) && (!cdp || (cdp.networks.includes("eip155:8453") && baseRoute === "cdp")) && !JSON.stringify(st).includes("-----BEGIN"),
    facs.map((f) => `${f.name}: ${f.ok ? `ok [${f.networks.map((n) => n.replace("eip155:", "")).join(",")}]` : f.error}`).join(" · ") + (cdp ? "" : " (CDP not configured)"),
  );

  const paid = await call("POST", "/v1/risk-check", { wallet: WALLET, chain: "base" }, { paid: true });
  if (paid.status === 0 || paid.status === 402) add("per_call_base", null, `not paid (status ${paid.status}): fund the payer`);
  else add("per_call_base", paid.status === 200 && typeof paid.json?.jws === "string" && !!settlementReceipt(paid.headers)?.transaction, `HTTP ${paid.status} score=${String(paid.json?.score)} ${paid.ms} ms end to end (402, payment, evaluation, settlement)`);

  const bought = await call("POST", "/v1/credits", { amount_usd: 0.1 }, { paid: true });
  const token = typeof bought.json?.token === "string" ? bought.json.token : "";
  const hashed = token ? `sha256:${createHash("sha256").update(token).digest("hex").slice(0, 12)}` : "none";
  if (bought.status === 0 || (bought.status === 402 && !token)) add("credits_buy", null, `not paid (status ${bought.status})`);
  else add("credits_buy", bought.status === 200 && /^x402c_[A-Za-z0-9_-]{43}$/.test(token) && bought.json?.balance_usd === "$0.10" && !!settlementReceipt(bought.headers)?.transaction, `HTTP ${bought.status} token ${hashed} balance=${String(bought.json?.balance_usd)} (one settlement for 100 checks)`);

  if (token) {
    const auth = { Authorization: `Bearer ${token}` };
    const first = await call("POST", "/v1/risk-check", { wallet: WALLET, chain: "base" }, { headers: auth });
    const second = await call("POST", "/v1/risk-check", { wallet: USER, chain: "base" }, { headers: auth });
    add(
      "credits_spend",
      first.status === 200 && second.status === 200 && first.headers.get("x-credits-charged") === "$0.001" && second.headers.get("x-credits-balance") === "$0.098" && !first.headers.get("payment-response") && typeof second.json?.jws === "string",
      `HTTP ${first.status}/${second.status} charged ${first.headers.get("x-credits-charged")} each; balance ${first.headers.get("x-credits-balance")} → ${second.headers.get("x-credits-balance")}; ${first.ms} ms and ${second.ms} ms, no payment round trip, no settlement (per call: ${paid.ms} ms)`,
    );
    const balance = await call("GET", "/v1/credits", undefined, { headers: auth });
    add("credits_balance", balance.status === 200 && balance.json?.balance_usd === "$0.098", `HTTP ${balance.status} balance=${String(balance.json?.balance_usd)}`);
    const big = { requests: new Array(25).fill({ wallet: USER, chain: "base", transaction: { from: USER, to: USER, value: "1" } }) };
    const refused = await call("POST", "/v1/risk-check/batch", big, { headers: auth });
    const after = await call("GET", "/v1/credits", undefined, { headers: auth });
    add("credits_insufficient", refused.status === 402 && refused.json?.error === "insufficient_credits" && refused.json?.cost_usd === "$0.125" && after.json?.balance_usd === "$0.098", `HTTP ${refused.status} ${String(refused.json?.error)} cost=${String(refused.json?.cost_usd)}; balance still ${String(after.json?.balance_usd)}`);
  } else {
    for (const id of ["credits_spend", "credits_balance", "credits_insufficient"]) add(id, null, "no token (the purchase did not complete)");
  }
  const malformed = await call("POST", "/v1/risk-check", { wallet: WALLET }, { headers: { Authorization: "Bearer x402c_nope" } });
  const unknown = await call("POST", "/v1/risk-check", { wallet: WALLET }, { headers: { Authorization: `Bearer x402c_${"Z".repeat(43)}` } });
  add("credits_bad_tokens", malformed.status === 401 && unknown.status === 402 && unknown.json?.error === "insufficient_credits", `malformed → ${malformed.status}; unknown token → ${unknown.status} ${String(unknown.json?.error)} (never an unpaid evaluation)`);

  // Who settled: each receipt's transaction sender on Base against the published signers.
  const signers = async (url: string) => {
    try {
      const j = (await (await fetch(`${url}/supported`, { signal: AbortSignal.timeout(10_000) })).json()) as { signers?: Record<string, string[]> };
      return new Set(Object.values(j.signers ?? {}).flat().map((a) => a.toLowerCase()));
    } catch {
      return new Set<string>();
    }
  };
  const [payaiSigners, dexterSigners] = await Promise.all([signers("https://facilitator.payai.network"), signers("https://x402.dexter.cash")]);
  const settledBy: Array<{ probe: string; transaction: string; from: string | null; facilitator: string }> = [];
  for (const rc of receipts.filter((x) => x.network === "eip155:8453" && x.transaction)) {
    let from: string | null = null;
    try {
      const res = await fetch("https://mainnet.base.org", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionByHash", params: [rc.transaction] }), signal: AbortSignal.timeout(10_000) });
      from = ((await res.json()) as { result?: { from?: string } }).result?.from?.toLowerCase() ?? null;
    } catch {
      from = null;
    }
    const facilitator = !from ? "unknown" : payaiSigners.has(from) ? "payai" : dexterSigners.has(from) ? "dexter" : "other (not PayAI or Dexter)";
    settledBy.push({ probe: rc.probe, transaction: rc.transaction as string, from, facilitator });
  }
  if (settledBy.length === 0) add("settled_by_routed_facilitator", null, "no Base settlement in this run");
  else {
    const expected = baseRoute === "cdp" ? "other (not PayAI or Dexter)" : baseRoute;
    add("settled_by_routed_facilitator", settledBy.every((x) => x.facilitator === expected), settledBy.map((x) => `${x.probe}: ${x.from?.slice(0, 10)}… → ${x.facilitator}`).join(" · ") + ` (Base route: ${baseRoute})`);
  }

  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    paid_via: process.env.PAY_NETWORK ?? "solana:*",
    summary: { pass: out.filter((o) => o.status === "PASS").length, fail: out.filter((o) => o.status === "FAIL").length, skip: out.filter((o) => o.status === "SKIP").length },
    outcomes: out,
    settlements: receipts,
    settled_by: settledBy,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/security-v5-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.summary));
  if (report.summary.fail > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

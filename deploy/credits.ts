import { formatUsd, priceMicro, SIMULATION_PRICE, simulates, toMicro } from "./pricing.js";
import { allChecked, fetchAdapter, json, payerOf, readCapped, recordSettlement, sanctionedPayer, settlementReceipt } from "./http-util.js";
import { claimPayment, paymentId, paymentVersion } from "./payment-claims.js";
import type { Stack } from "./protected.js";
import type { DurableObjectState, WorkerEnv } from "./runtime.js";
import type { HTTPProcessResult } from "@x402/core/http";

// Prepaid credits: one x402 payment buys a USD balance, and each check then debits it with
// no 402 round trip and no on-chain settlement. A settlement costs the same whether it
// carries $0.0035 or $5 (PayAI bills gas + 30% per settlement on Base), so a prepaid
// balance is where a check can cost $0.001 and still leave a margin. It is not a free tier:
// every check is paid, in advance.
//
//   POST /v1/credits {"amount_usd": 1}                  → 402, then pay → {token, balance_usd}
//   POST /v1/credits {"amount_usd": 5} + Authorization  → tops up that token
//   GET  /v1/credits + Authorization: Bearer x402c_…    → balance
//   POST /v1/risk-check + Authorization: Bearer x402c_… → debits the balance, no payment round trip
//
// The token is a bearer credential: it is shown once, stored only as its SHA-256 (the
// ledger's Durable Object name), and never logged.

export const CREDIT_TOKEN_PREFIX = "x402c_";
/** Price of a check paid from credits; one that simulates a transaction costs SIMULATION_PRICE. */
export const CREDIT_CHECK_PRICE = 0.001;
export const CREDIT_PACK_MIN_USD = 0.1;
export const CREDIT_PACK_MAX_USD = 100;

export type CreditPricing = { check_usd: string; simulated_check_usd: string; pack_min_usd: string; pack_max_usd: string; endpoint: string };
export const CREDIT_PRICING: CreditPricing = {
  check_usd: String(CREDIT_CHECK_PRICE),
  simulated_check_usd: String(SIMULATION_PRICE),
  pack_min_usd: String(CREDIT_PACK_MIN_USD),
  pack_max_usd: String(CREDIT_PACK_MAX_USD),
  endpoint: "/v1/credits",
};

/** One token's balance in micro-USD. A Durable Object serializes every operation, so a debit can never overdraw it. */
export class CreditLedger {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const op = new URL(request.url).pathname.slice(1);
    const body = request.method === "POST" ? ((await request.json().catch(() => ({}))) as { micro?: unknown; ref?: unknown }) : {};
    const micro = typeof body.micro === "number" && Number.isSafeInteger(body.micro) && body.micro > 0 ? body.micro : null;
    const balance = (await this.state.storage.get<number>("balance")) ?? 0;
    if (op === "balance") return Response.json({ micro: balance });
    if (micro === null) return Response.json({ error: "bad_amount" }, { status: 400 });
    if (op === "credit") {
      // A settlement credits once, however often its response is retried.
      const ref = typeof body.ref === "string" && body.ref ? `ref:${body.ref}` : null;
      if (ref && (await this.state.storage.get(ref)) !== undefined) return Response.json({ micro: balance, duplicate: true });
      await this.state.storage.put({ balance: balance + micro, ...(ref ? { [ref]: micro } : {}) });
      return Response.json({ micro: balance + micro });
    }
    if (op === "debit") {
      if (balance < micro) return Response.json({ micro: balance, insufficient: true }, { status: 402 });
      await this.state.storage.put("balance", balance - micro);
      return Response.json({ micro: balance - micro });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  }
}

/** The credit token in `Authorization: Bearer x402c_…`, if any. */
export function creditToken(request: Request): string | null {
  const m = /^Bearer\s+(x402c_[A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization")?.trim() ?? "");
  return m ? (m[1] as string) : null;
}

export function newCreditToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return CREDIT_TOKEN_PREFIX + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A token's ledger name: its SHA-256 (the token itself is never stored). */
async function ledgerName(token: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function ledgerCall(env: WorkerEnv, token: string, op: "balance" | "credit" | "debit", body?: { micro: number; ref?: string }): Promise<{ status: number; micro: number; insufficient?: boolean }> {
  return ledgerCallByName(env, await ledgerName(token), op, body);
}

async function ledgerCallByName(env: WorkerEnv, name: string, op: "balance" | "credit" | "debit", body?: { micro: number; ref?: string }): Promise<{ status: number; micro: number; insufficient?: boolean }> {
  const ns = env.CREDITS;
  if (!ns) throw new Error("credits are not configured");
  const stub = ns.get(ns.idFromName(name));
  const res = await stub.fetch(`https://ledger/${op}`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
  const out = (await res.json()) as { micro?: number; insufficient?: boolean };
  if (res.status >= 500 || (res.status >= 400 && !out.insufficient)) throw new Error(`ledger ${op}: HTTP ${res.status}`);
  return { status: res.status, micro: out.micro ?? 0, ...(out.insufficient ? { insufficient: true } : {}) };
}

/** A settled pack whose credit did not go through yet: retried by the cron until the ledger takes it. */
const PENDING_PREFIX = "pc:";

/** Credits a settled pack, retrying; if the ledger still fails, the credit is queued (idempotent by settlement ref). */
async function creditSettled(env: WorkerEnv, token: string, micro: number, ref: string | null): Promise<{ micro: number } | { pending: true }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await ledgerCall(env, token, "credit", { micro, ...(ref ? { ref } : {}) });
    } catch (err) {
      console.error(`credit after settlement failed (attempt ${attempt + 1}): ${String(err).slice(0, 120)}`);
      if (attempt < 2) await new Promise((r) => setTimeout(r, 200 * 3 ** attempt));
    }
  }
  const key = `${PENDING_PREFIX}${ref ?? crypto.randomUUID()}`;
  await env.RATE?.put(key, JSON.stringify({ name: await ledgerName(token), micro, ref, at: new Date().toISOString() }), { expirationTtl: 30 * 86400 });
  return { pending: true };
}

/** The cron's pass over queued credits: each is applied once (by its settlement ref) and then removed. */
export async function retryPendingCredits(env: WorkerEnv): Promise<number> {
  const kv = env.RATE;
  if (!kv?.list || !kv.delete || !env.CREDITS) return 0;
  let applied = 0;
  const { keys } = await kv.list({ prefix: PENDING_PREFIX, limit: 50 });
  for (const { name: key } of keys) {
    const raw = await kv.get(key);
    if (!raw) continue;
    const entry = JSON.parse(raw) as { name: string; micro: number; ref: string | null };
    try {
      await ledgerCallByName(env, entry.name, "credit", { micro: entry.micro, ...(entry.ref ? { ref: entry.ref } : {}) });
      await kv.delete(key);
      applied++;
    } catch (err) {
      console.error(`queued credit still failing: ${String(err).slice(0, 120)}`);
    }
  }
  return applied;
}

/** A pack's price from the request body: $0.10–$100 in whole cents, else null. */
export function packMicro(body: unknown): number | null {
  const amount = (body as { amount_usd?: unknown } | null)?.amount_usd;
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < CREDIT_PACK_MIN_USD || amount > CREDIT_PACK_MAX_USD) return null;
  const micro = toMicro(amount);
  return micro % 10_000 === 0 ? micro : null;
}

/** Cost of a (validated) evaluation request paid from credits, in micro-USD. */
export function creditCostMicro(path: string, body: unknown, simulation: boolean): number {
  return priceMicro(path, body, toMicro(CREDIT_CHECK_PRICE), simulation);
}

/**
 * An evaluation paid from credits: debit first (atomic; an overdraw is refused), evaluate,
 * and refund when no verdict was produced (the same rule as a paid call: never charge for
 * a verdict that does not exist).
 */
export async function spendCredits(env: WorkerEnv, token: string, path: string, parsed: unknown, serve: () => Promise<Response>, ctx?: { waitUntil(promise: Promise<unknown>): void }): Promise<Response> {
  if (!env.CREDITS) return json(503, { error: "credits_unavailable" });
  const cost = creditCostMicro(path, parsed, env.SIMULATION !== "off");
  let debit: Awaited<ReturnType<typeof ledgerCall>>;
  try {
    debit = await ledgerCall(env, token, "debit", { micro: cost });
  } catch {
    return json(503, { error: "credits_unavailable" }, { "Retry-After": "5" });
  }
  if (debit.insufficient) {
    return json(402, { error: "insufficient_credits", balance_usd: formatUsd(debit.micro), cost_usd: formatUsd(cost), top_up: "POST /v1/credits {\"amount_usd\": 1} with this token" });
  }
  const refund = (micro = cost) =>
    ledgerCall(env, token, "credit", { micro, ref: `refund:${crypto.randomUUID()}` }).catch((err: unknown) => {
      console.error(`credit refund failed: ${String(err).slice(0, 120)}`);
      return null;
    });
  // The refund decision runs to completion even if the caller disconnects mid-evaluation (waitUntil).
  const work = (async (): Promise<Response> => {
    let res: Response;
    try {
      res = await serve();
    } catch (err) {
      console.error(`evaluation paid from credits threw: ${String(err).slice(0, 160)}`);
      const back = await refund();
      return json(503, { error: "evaluation_unavailable", detail: "no charge: the evaluation could not be completed" }, { "Retry-After": "5", ...(back ? { "X-Credits-Balance": formatUsd(back.micro) } : {}) });
    }
    if (res.status !== 200 || !(await allChecked(res.clone()))) {
      const back = await refund();
      const headers = back ? { "X-Credits-Balance": formatUsd(back.micro) } : {};
      if (res.status !== 200) {
        for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
        return res;
      }
      return json(503, { error: "evaluation_unavailable", detail: "no charge: the evaluation could not be completed" }, { "Retry-After": "5", ...headers });
    }
    // The simulation surcharge is charged only for simulations that ran.
    const surcharge = env.SIMULATION !== "off" ? await unsimulatedSurcharge(path, parsed, res.clone()) : 0;
    let balance = debit.micro;
    let charged = cost;
    if (surcharge > 0) {
      const back = await refund(surcharge);
      if (back) {
        balance = back.micro;
        charged = cost - surcharge;
      }
    }
    res.headers.set("X-Credits-Charged", formatUsd(charged));
    res.headers.set("X-Credits-Balance", formatUsd(balance));
    return res;
  })();
  ctx?.waitUntil(work.catch(() => undefined));
  return work;
}

/** The surcharge (simulation price minus a plain check) of every item priced as simulated whose simulation did not run. */
async function unsimulatedSurcharge(path: string, parsed: unknown, res: Response): Promise<number> {
  const items = path.endsWith("/batch") ? (((parsed as { requests?: unknown[] } | null)?.requests ?? []) as unknown[]) : [parsed];
  let results: Array<{ evidence?: { simulation?: { status?: unknown } } }>;
  try {
    const body = (await res.json()) as { results?: unknown[] } & Record<string, unknown>;
    results = (Array.isArray(body.results) ? body.results : [body]) as typeof results;
  } catch {
    return 0;
  }
  const extra = Math.max(0, toMicro(SIMULATION_PRICE) - toMicro(CREDIT_CHECK_PRICE));
  return items.reduce<number>((sum, item, i) => {
    const status = results[i]?.evidence?.simulation?.status;
    return simulates(item) && status !== "ok" && status !== "reverted" ? sum + extra : sum;
  }, 0);
}

/** GET /v1/credits (balance) and POST /v1/credits (buy or top up a balance, paid via x402). */
export async function handleCredits(request: Request, env: WorkerEnv, stack: Stack): Promise<Response> {
  if (!env.CREDITS) return json(503, { error: "credits_unavailable" });
  const token = creditToken(request);
  if (request.method === "GET") {
    if (!token) return json(401, { error: "credit_token_required", detail: "Authorization: Bearer x402c_…", buy: 'POST /v1/credits {"amount_usd": 1} with any x402 client: the response carries a token, shown once', docs: "https://x402check.xyz/#pricing" });
    try {
      const { micro } = await ledgerCall(env, token, "balance");
      return json(200, { balance_usd: formatUsd(micro), pricing: CREDIT_PRICING }, { "Cache-Control": "no-store" });
    } catch (err) {
      console.error(`credit balance failed: ${String(err).slice(0, 120)}`);
      return json(503, { error: "credits_unavailable" }, { "Retry-After": "5", "Cache-Control": "no-store" });
    }
  }
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  const bytes = await readCapped(request, 1024);
  if (!bytes) return json(413, { error: "body_too_large", max_bytes: 1024 });
  const text = new TextDecoder().decode(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text || "{}");
  } catch {
    return json(422, { error: "invalid_request", field: "body" });
  }
  const micro = packMicro(parsed);
  if (micro === null) return json(422, { error: "invalid_request", field: "amount_usd", detail: `a number of dollars from ${CREDIT_PACK_MIN_USD} to ${CREDIT_PACK_MAX_USD}, in whole cents` });
  if (request.headers.get("authorization") && !token) return json(422, { error: "invalid_request", field: "authorization", detail: "Bearer x402c_… (a token from this endpoint), or none for a new one" });
  // Only x402 v2 payments (what the challenge offers); anything else gets the v2 challenge.
  const header = request.headers.get("PAYMENT-SIGNATURE");
  const payment = header && paymentVersion(header) === 2 ? header : null;
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest({
      adapter: fetchAdapter(request, parsed),
      path: "/v1/credits",
      method: "POST",
      ...(payment ? { paymentHeader: payment } : {}),
    });
  } catch (err) {
    console.error(`payment processing failed on /v1/credits: ${String(err).slice(0, 200)}`);
    return json(500, { error: "payment_processing_failed" });
  }
  if (result.type === "payment-error") return new Response(typeof result.response.body === "string" ? result.response.body : JSON.stringify(result.response.body), { status: result.response.status, headers: result.response.headers });
  if (result.type === "no-payment-required") return json(402, { error: "payment_required" });
  if (sanctionedPayer(payerOf(result.paymentPayload))) return json(403, { error: "payer_sanctioned", detail: "the paying wallet is on the OFAC SDN list; nothing was charged" });
  // Single use: one payment buys one pack, however often it is sent.
  const claim = await claimPayment(env, await paymentId(payment));
  if (!claim.claimed) {
    return claim.reason === "duplicate"
      ? json(409, { error: "payment_already_used", detail: "this payment was already presented; sign a new one" })
      : json(503, { error: "payment_claims_unavailable", detail: "no charge: retry shortly" }, { "Retry-After": "5" });
  }
  let reason = "settlement_failed";
  let settle: Awaited<ReturnType<Stack["http"]["processSettlement"]>> | null = null;
  try {
    settle = await stack.http.processSettlement(result.paymentPayload, result.paymentRequirements);
    if (!settle.success) reason = settle.errorReason ?? reason;
  } catch (err) {
    console.error(`settlement failed on /v1/credits: ${String(err).slice(0, 200)}`);
  }
  if (!settle?.success) {
    await claim.release();
    console.warn(`credit pack settlement refused: ${reason}`);
    return json(402, { error: "payment_settlement_failed" }, { "X-Payment-Error": reason });
  }
  // Settled: from here on the buyer has paid, so they always leave with their token.
  await claim.settled();
  const receipt = settlementReceipt(settle.headers);
  if (receipt) await recordSettlement(env, { path: "/v1/credits", network: receipt.network, transaction: receipt.transaction, micro });
  const owner = token ?? newCreditToken();
  const credited = await creditSettled(env, owner, micro, receipt ? `${receipt.network}:${receipt.transaction}` : null);
  const body = {
    ...(token ? {} : { token: owner }),
    credited_usd: formatUsd(micro),
    ...("pending" in credited
      ? { status: "pending", detail: "the payment settled; the balance is being credited and will show within a few minutes" }
      : { balance_usd: formatUsd(credited.micro) }),
    pricing: CREDIT_PRICING,
    usage: "send Authorization: Bearer <token> with POST /v1/risk-check or /v1/risk-check/batch; the token is shown once: store it like a password",
  };
  const res = json("pending" in credited ? 202 : 200, body, { "Cache-Control": "no-store" });
  for (const [k, v] of Object.entries(settle.headers)) res.headers.set(k, v);
  return res;
}

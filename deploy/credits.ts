import { formatUsd, priceMicro, SIMULATION_PRICE, toMicro } from "./pricing.js";
import { allChecked, fetchAdapter, json } from "./http-util.js";
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

async function ledgerCall(env: WorkerEnv, token: string, op: "balance" | "credit" | "debit", body?: { micro: number; ref?: string }): Promise<{ status: number; micro: number; insufficient?: boolean }> {
  const ns = env.CREDITS;
  if (!ns) throw new Error("credits are not configured");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  const name = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  const stub = ns.get(ns.idFromName(name));
  const res = await stub.fetch(`https://ledger/${op}`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
  const out = (await res.json()) as { micro?: number; insufficient?: boolean };
  return { status: res.status, micro: out.micro ?? 0, ...(out.insufficient ? { insufficient: true } : {}) };
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
export async function spendCredits(env: WorkerEnv, token: string, path: string, parsed: unknown, serve: () => Promise<Response>): Promise<Response> {
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
  const refund = () => ledgerCall(env, token, "credit", { micro: cost, ref: `refund:${crypto.randomUUID()}` }).catch(() => null);
  const res = await serve();
  if (res.status !== 200 || !(await allChecked(res.clone()))) {
    const back = await refund();
    const headers = back ? { "X-Credits-Balance": formatUsd(back.micro) } : {};
    if (res.status !== 200) {
      for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
      return res;
    }
    return json(503, { error: "evaluation_unavailable", detail: "no charge: the evaluation could not be completed" }, { "Retry-After": "5", ...headers });
  }
  res.headers.set("X-Credits-Charged", formatUsd(cost));
  res.headers.set("X-Credits-Balance", formatUsd(debit.micro));
  return res;
}

/** GET /v1/credits (balance) and POST /v1/credits (buy or top up a balance, paid via x402). */
export async function handleCredits(request: Request, env: WorkerEnv, stack: Stack): Promise<Response> {
  if (!env.CREDITS) return json(503, { error: "credits_unavailable" });
  const token = creditToken(request);
  if (request.method === "GET") {
    if (!token) return json(401, { error: "credit_token_required", detail: "Authorization: Bearer x402c_…" });
    const { micro } = await ledgerCall(env, token, "balance");
    return json(200, { balance_usd: formatUsd(micro), pricing: CREDIT_PRICING }, { "Cache-Control": "no-store" });
  }
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  const text = await request.text();
  if (text.length > 1024) return json(413, { error: "body_too_large", max_bytes: 1024 });
  let parsed: unknown;
  try {
    parsed = JSON.parse(text || "{}");
  } catch {
    return json(422, { error: "invalid_request", field: "body" });
  }
  const micro = packMicro(parsed);
  if (micro === null) return json(422, { error: "invalid_request", field: "amount_usd", detail: `a number of dollars from ${CREDIT_PACK_MIN_USD} to ${CREDIT_PACK_MAX_USD}, in whole cents` });
  if (request.headers.get("authorization") && !token) return json(422, { error: "invalid_request", field: "authorization", detail: "Bearer x402c_… (a token from this endpoint), or none for a new one" });
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest({
      adapter: fetchAdapter(request, parsed),
      path: "/v1/credits",
      method: "POST",
      ...(request.headers.get("PAYMENT-SIGNATURE") ? { paymentHeader: request.headers.get("PAYMENT-SIGNATURE") as string } : {}),
    });
  } catch {
    return json(500, { error: "payment_processing_failed" });
  }
  if (result.type === "payment-error") return new Response(typeof result.response.body === "string" ? result.response.body : JSON.stringify(result.response.body), { status: result.response.status, headers: result.response.headers });
  if (result.type === "no-payment-required") return json(402, { error: "payment_required" });
  let reason = "settlement_failed";
  try {
    const settle = await stack.http.processSettlement(result.paymentPayload, result.paymentRequirements);
    if (settle.success) {
      const receipt = settlementRef(settle.headers);
      const owner = token ?? newCreditToken();
      const credited = await ledgerCall(env, owner, "credit", { micro, ...(receipt ? { ref: receipt } : {}) });
      const res = json(200, {
        ...(token ? {} : { token: owner }),
        credited_usd: formatUsd(micro),
        balance_usd: formatUsd(credited.micro),
        pricing: CREDIT_PRICING,
        usage: "send Authorization: Bearer <token> with POST /v1/risk-check or /v1/risk-check/batch; the token is shown once: store it like a password",
      }, { "Cache-Control": "no-store" });
      for (const [k, v] of Object.entries(settle.headers)) res.headers.set(k, v);
      return res;
    }
    reason = settle.errorReason ?? reason;
  } catch {
    // fall through to 402
  }
  return json(402, { error: "payment_settlement_failed" }, { "X-Payment-Error": reason });
}

/** The settlement's transaction id, from the PAYMENT-RESPONSE header: it makes crediting idempotent. */
function settlementRef(headers: Record<string, string>): string | null {
  const raw = headers["PAYMENT-RESPONSE"] ?? headers["payment-response"] ?? headers["X-PAYMENT-RESPONSE"];
  if (!raw) return null;
  try {
    const r = JSON.parse(atob(raw)) as { transaction?: unknown; network?: unknown };
    return typeof r.transaction === "string" && r.transaction ? `${String(r.network ?? "")}:${r.transaction}` : null;
  } catch {
    return null;
  }
}

import { generateKeyPair, type KeyPair } from "../src/jws.js";
import { Provider, type PricingInfo } from "../src/provider.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient } from "../src/jev.js";
import type { HandlerDeps } from "../src/handler.js";
import { validateBatch, validateRequest } from "../src/validate.js";
import { createOnchainLookup } from "../src/onchain.js";
import { createSimulator } from "../src/simulation.js";
import { createContractIntel } from "../src/contract-intel.js";
import { SOLANA_DEVNET, SOLANA_MAINNET } from "../src/chains.js";
import type { ThreatIntelFeeds } from "../src/threat-intel.js";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { x402HTTPResourceServer, type HTTPAdapter, type HTTPRequestContext, type HTTPProcessResult, type HTTPResponseInstructions, type PaymentOption } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import type { WorkerEnv } from "./runtime.js";

export const PROTECTED = new Set(["/v1/risk-check", "/v1/risk-check/batch"]);
const DEFAULT_FACILITATOR = "https://x402.org/facilitator";
const DEFAULT_MAINNET_FACILITATOR = "https://x402.dexter.cash";
const DEFAULT_PAYAI_FACILITATOR = "https://facilitator.payai.network";
const BASE_MAINNET = "eip155:8453";
const BASE_SEPOLIA = "eip155:84532";
const MAX_BODY_BYTES = 64 * 1024;
export const UNIT_PRICE_EVM = 0.001;
// Solana mainnet settlement via Dexter has a dynamic floor above $0.001.
export const UNIT_PRICE_SOL = 0.002;

export type Stack = {
  deps: HandlerDeps;
  http: x402HTTPResourceServer;
};

let cached: { key: string; stack: Stack } | null = null;
let pending: { key: string; promise: Promise<Stack> } | null = null;

function loadKeyPair(env: WorkerEnv): KeyPair {
  if (env.JEV_ATTEST_PRIVATE_KEY && env.JEV_ATTEST_PUBLIC_JWK) {
    const jwk = JSON.parse(env.JEV_ATTEST_PUBLIC_JWK) as KeyPair["publicJwk"];
    if (jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string") {
      return { privatePem: env.JEV_ATTEST_PRIVATE_KEY, publicJwk: jwk };
    }
  }
  return generateKeyPair("jev-attest-v1");
}

/** Units billed for a validated body: 1 per evaluation (batch = number of items). */
export function unitsFor(path: string, body: unknown): number {
  if (!path.endsWith("/batch")) return 1;
  const n = Array.isArray((body as { requests?: unknown } | null)?.requests) ? (body as { requests: unknown[] }).requests.length : 1;
  return Math.min(25, Math.max(1, n));
}

export function makePrice(unit: number): (ctx: HTTPRequestContext) => string {
  return (ctx) => `$${(unit * unitsFor(ctx.path, ctx.adapter.getBody?.())).toFixed(3)}`;
}

export function buildAccepts(env: WorkerEnv): PaymentOption[] {
  const payToEvm = env.PAY_TO_EVM ?? "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  const payToSol = env.PAY_TO_SOL ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
  const evm = makePrice(UNIT_PRICE_EVM);
  const accepts: PaymentOption[] = [
    { scheme: "exact", network: BASE_MAINNET, payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:137", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:42161", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:43114", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:143", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:1329", payTo: payToEvm, price: evm },
    { scheme: "exact", network: SOLANA_MAINNET, payTo: payToSol, price: makePrice(UNIT_PRICE_SOL) },
  ];
  if (env.ENABLE_TESTNETS === "true") {
    accepts.push(
      { scheme: "exact", network: BASE_SEPOLIA, payTo: payToEvm, price: evm },
      { scheme: "exact", network: "eip155:421614", payTo: payToEvm, price: evm },
      { scheme: "exact", network: SOLANA_DEVNET, payTo: payToSol, price: evm },
    );
  }
  return accepts;
}

function stackKey(env: WorkerEnv): string {
  return JSON.stringify([
    env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY, env.JEV_ATTEST_PUBLIC_JWK,
    env.PAY_TO_EVM, env.PAY_TO_SOL, env.X402_FACILITATOR_URL, env.X402_FACILITATOR_URL_MAINNET, env.X402_FACILITATOR_URL_PAYAI,
    env.ENABLE_TESTNETS, env.ONCHAIN, env.RPC_URLS, env.SOL_RPC_URL_MAINNET, env.SIMULATION, env.SIMULATION_RPC_URLS, env.CONTRACT_INTEL,
  ]);
}

export function buildStack(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>): Stack {
  const host = env.PROVIDER_HOST ?? "x402check.xyz";
  const jev = env.TYPESAFE_API_KEY
    ? new JevClient({ apiKey: env.TYPESAFE_API_KEY })
    : env.AI_GATEWAY_API_KEY
      ? new GatewayJevClient()
      : null;
  let rpc: Record<string, string> = {};
  try {
    rpc = env.RPC_URLS ? (JSON.parse(env.RPC_URLS) as Record<string, string>) : {};
  } catch {
    rpc = {};
  }
  if (env.SOL_RPC_URL_MAINNET) rpc[SOLANA_MAINNET] = env.SOL_RPC_URL_MAINNET;
  // Runs in parallel with the model call (~0.5 s), so a 2 s ceiling only matters when an RPC is slow.
  const onchain = env.ONCHAIN === "off" ? null : createOnchainLookup({ rpc, timeoutMs: 2000 });
  let simRpc: Record<string, string> = {};
  try {
    simRpc = env.SIMULATION_RPC_URLS ? (JSON.parse(env.SIMULATION_RPC_URLS) as Record<string, string>) : {};
  } catch {
    simRpc = {};
  }
  const contractIntel = env.CONTRACT_INTEL === "off" ? null : createContractIntel({ timeoutMs: 1500 });
  const simulator = env.SIMULATION === "off" ? null : createSimulator({ rpc: simRpc, timeoutMs: 2500, contractIntel });
  const accepts = buildAccepts(env);
  const pricing: PricingInfo = { unitUsd: UNIT_PRICE_EVM.toFixed(3), networks: accepts.map((a) => String(a.network)) };
  const deps: HandlerDeps = { provider: new Provider({ host, keyPair: loadKeyPair(env), jev, onchain, feeds, simulator, contractIntel }), pricing };

  const facilitators = [
    new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_MAINNET ?? DEFAULT_MAINNET_FACILITATOR }),
    new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_PAYAI ?? DEFAULT_PAYAI_FACILITATOR }),
    ...(env.ENABLE_TESTNETS === "true" ? [new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR })] : []),
  ];
  const resourceServer = new x402ResourceServer(facilitators);
  resourceServer.register("eip155:*", new ExactEvmScheme());
  resourceServer.register(SOLANA_MAINNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL_MAINNET ?? "https://api.mainnet-beta.solana.com" }));
  if (env.ENABLE_TESTNETS === "true") {
    resourceServer.register(SOLANA_DEVNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL ?? "https://api.devnet.solana.com" }));
  }
  const routes = {
    "POST /v1/risk-check": { accepts, description: "x402check risk check with signed attestation", mimeType: "application/json" },
    "POST /v1/risk-check/batch": { accepts, description: "Batch risk check (up to 25 requests, billed per item)", mimeType: "application/json" },
  };
  return { deps, http: new x402HTTPResourceServer(resourceServer, routes) };
}

export async function ensureStack(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>): Promise<Stack> {
  const key = stackKey(env);
  if (cached?.key === key) return cached.stack;
  if (pending?.key !== key) {
    const stack = buildStack(env, feeds);
    pending = {
      key,
      promise: stack.http.initialize().then(
        () => stack,
        () => stack, // facilitator discovery failure surfaces later as a payment_processing_failed 500
      ),
    };
  }
  const stack = await pending.promise;
  cached = { key, stack };
  return stack;
}

export function fetchAdapter(request: Request, body: unknown): HTTPAdapter {
  return {
    getHeader: (name) => request.headers.get(name) ?? undefined,
    getMethod: () => request.method,
    getPath: () => new URL(request.url).pathname,
    getUrl: () => request.url,
    getAcceptHeader: () => request.headers.get("accept") ?? "*/*",
    getUserAgent: () => request.headers.get("user-agent") ?? "",
    getBody: () => body,
  };
}

function instructionsToResponse(instr: HTTPResponseInstructions): Response {
  return new Response(typeof instr.body === "string" ? instr.body : JSON.stringify(instr.body), {
    status: instr.status,
    headers: instr.headers,
  });
}

/**
 * Quota identity for a client IP. IPv6 is aggregated to its /64: a single host
 * controls a whole /64, so per-address keys would make every limit unbounded.
 */
export function quotaIpKey(ip: string): string {
  if (!ip.includes(":")) return ip;
  const [head = "", tail] = ip.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  if (t.length && t[t.length - 1]!.includes(".")) t.splice(t.length - 1, 1, "0", "0"); // embedded IPv4 = 2 groups
  const groups = tail === undefined ? h : [...h, ...Array<string>(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
  const prefix = groups.slice(0, 4).map((g) => (Number.parseInt(g || "0", 16) || 0).toString(16));
  while (prefix.length < 4) prefix.push("0");
  return `${prefix.join(":")}::/64`;
}

const NEW_CLIENT_BUDGET_DAILY = 1000;
// Caps how many fresh client ids one IP (/64) can mint per day.
const NEW_CLIENTS_PER_IP_DAILY = 10;

type ConsumeResult = { allowed: boolean; remaining: number };

async function doConsume(env: WorkerEnv, key: string, daily: number, cost: number, admit?: { key: string; daily: number }[]): Promise<ConsumeResult | null> {
  if (!env.COUNTER) return null;
  const day = new Date().toISOString().slice(0, 10);
  try {
    const stub = env.COUNTER.get(env.COUNTER.idFromName("quota"));
    const res = await stub.fetch("https://counter/consume", {
      method: "POST",
      body: JSON.stringify({ op: "consume", key, day, daily, cost, ...(admit ? { admit } : {}) }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as ConsumeResult;
    return { allowed: data.allowed, remaining: data.remaining };
  } catch {
    return null;
  }
}

export async function doTotal(env: WorkerEnv): Promise<number | null> {
  if (!env.COUNTER) return null;
  const day = new Date().toISOString().slice(0, 10);
  try {
    const stub = env.COUNTER.get(env.COUNTER.idFromName("quota"));
    const res = await stub.fetch("https://counter/total", { method: "POST", body: JSON.stringify({ op: "total", day }) });
    if (!res.ok) return null;
    return ((await res.json()) as { total: number }).total;
  } catch {
    return null;
  }
}

function freeDaily(env: WorkerEnv): number {
  const daily = Number(env.FREE_TIER_DAILY ?? "25");
  return Number.isFinite(daily) && daily > 0 ? daily : 0;
}

/** Charges `units` free evaluations; fail-closed (not granted) when the counter is unavailable. */
export async function chargeFreeTier(env: WorkerEnv, ipKey: string, clientId: string, units: number): Promise<{ granted: boolean; remaining: number }> {
  const daily = freeDaily(env);
  if (daily <= 0) return { granted: false, remaining: 0 };
  if (clientId) {
    const viaClient = await doConsume(env, `client:${clientId}`, daily, units, [
      { key: "client-new:global", daily: NEW_CLIENT_BUDGET_DAILY },
      { key: `client-new-ip:${ipKey}`, daily: NEW_CLIENTS_PER_IP_DAILY },
    ]);
    if (viaClient?.allowed) return { granted: true, remaining: viaClient.remaining };
    // A denied or exhausted client id falls back to the caller's IP allowance, so
    // draining the global new-client budget cannot lock real new installs out.
  }
  const viaIp = await doConsume(env, `ip:${ipKey}`, daily, units);
  return { granted: viaIp?.allowed === true, remaining: viaIp?.remaining ?? 0 };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers });
}

async function readCapped(request: Request, max: number): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

async function allChecked(res: Response): Promise<boolean> {
  try {
    const body = (await res.json()) as { checked?: unknown; results?: Array<{ checked?: unknown }> };
    if (Array.isArray(body.results)) return body.results.length > 0 && body.results.every((r) => r.checked === true);
    return body.checked === true;
  } catch {
    return false;
  }
}

export async function handleProtected(request: Request, env: WorkerEnv, stack: Stack, serve: (req: Request) => Promise<Response>): Promise<Response> {
  const path = new URL(request.url).pathname;
  // 1. Read and validate before any quota or payment work: invalid input never
  //    costs the caller a free slot and is never priced. The cap is in BYTES and is
  //    enforced while streaming, so an oversized body is never fully buffered.
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return json(413, { error: "body_too_large", max_bytes: MAX_BODY_BYTES });
  const bytes = await readCapped(request, MAX_BODY_BYTES);
  if (!bytes) return json(413, { error: "body_too_large", max_bytes: MAX_BODY_BYTES });
  const text = new TextDecoder().decode(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return json(422, { error: "invalid_request", field: "body" });
  }
  if (path.endsWith("/batch")) {
    const v = validateBatch(parsed);
    if (!v.ok) return json(v.status, v.body);
  } else {
    const v = validateRequest(parsed);
    if (!v.ok) return json(422, { error: "invalid_request", field: v.field });
  }
  const units = unitsFor(path, parsed);
  const replay = () => new Request(request.url, { method: "POST", headers: request.headers, body: text });

  // 2. Free tier: charged per evaluation (a batch of n costs n slots). Only the x402 v2
  //    PAYMENT-SIGNATURE header counts as a payment attempt: the SDK in use does not read
  //    X-PAYMENT, so honouring it here would skip the free tier for a payment that can
  //    never be processed.
  const paymentHeader = request.headers.get("PAYMENT-SIGNATURE");
  const forcePaid = (request.headers.get("X-Risk-Check-Paid") ?? "").trim().length > 0;
  if (!paymentHeader && !forcePaid) {
    const clientId = (request.headers.get("X-Risk-Check-Client") ?? "").trim().slice(0, 64);
    const ipKey = quotaIpKey(request.headers.get("CF-Connecting-IP") ?? "unknown");
    const free = await chargeFreeTier(env, ipKey, clientId, units);
    if (free.granted) {
      const res = await serve(replay());
      res.headers.set("X-Risk-Check-Free", "true");
      res.headers.set("X-Risk-Check-Free-Remaining", String(free.remaining));
      return res;
    }
  }

  // 3. Paid path: price = unit price × units; the result is released only after settlement.
  const ctx: HTTPRequestContext = {
    adapter: fetchAdapter(request, parsed),
    path,
    method: request.method,
    ...(paymentHeader ? { paymentHeader } : {}),
  };
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest(ctx);
  } catch {
    return json(500, { error: "payment_processing_failed" });
  }
  if (result.type === "payment-error") return instructionsToResponse(result.response);
  if (result.type === "no-payment-required") return json(402, { error: "payment_required" });
  const res = await serve(replay());
  if (res.status !== 200) return res;
  // Never charge for a verdict that was not produced: every result must be checked.
  if (!(await allChecked(res.clone()))) {
    return json(503, { error: "evaluation_unavailable", detail: "no charge: the evaluation could not be completed" }, { "Retry-After": "5" });
  }
  // Settle before releasing the result: a payload that verifies but cannot settle
  // (replayed authorization, funds moved between verify and settle) must not
  // receive a signed attestation.
  let reason = "settlement_failed";
  try {
    const settle = await stack.http.processSettlement(result.paymentPayload, result.paymentRequirements);
    if (settle.success) {
      for (const [k, v] of Object.entries(settle.headers)) res.headers.set(k, v);
      return res;
    }
    reason = settle.errorReason ?? reason;
  } catch {
    // fall through to 402
  }
  return json(402, { error: "payment_settlement_failed" }, { "X-Payment-Error": reason });
}

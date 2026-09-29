import { generateKeyPair, type KeyPair } from "../src/jws.js";
import { Provider, type PricingInfo } from "../src/provider.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient } from "../src/jev.js";
import type { HandlerDeps } from "../src/handler.js";
import { validateBatch, validateRequest } from "../src/validate.js";
import { createOnchainLookup } from "../src/onchain.js";
import { createSimulator } from "../src/simulation.js";
import { createContractIntel } from "../src/contract-intel.js";
import { kitWatchLookup } from "./kit-watch.js";
import { normalizeChain, SOLANA_DEVNET, SOLANA_MAINNET } from "../src/chains.js";
import { parseSubject } from "../src/address.js";
import { SIMULATION_ENDPOINTS } from "../src/rpc.js";
import type { ThreatIntelFeeds } from "../src/threat-intel.js";
import { HTTPFacilitatorClient, x402ResourceServer, type FacilitatorClient } from "@x402/core/server";
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
/**
 * An evaluation that simulates a transaction (eth_simulateV1, classification of every
 * recipient and spender, code fingerprints through delegations and proxies): the most
 * valuable and most expensive layer. Charged only when the simulation can run.
 */
export const SIMULATION_PRICE = 0.005;

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

/** Whether this (raw, validated) request item will be simulated: a transaction on a chain with a simulation endpoint. */
export function simulates(item: unknown): boolean {
  if (!item || typeof item !== "object") return false;
  const r = item as { transaction?: unknown; chain?: unknown; wallet?: unknown };
  if (r.transaction === undefined) return false;
  const network = typeof r.chain === "string" ? normalizeChain(r.chain)?.caip2 : typeof r.wallet === "string" ? parseSubject(r.wallet)?.caip2 : undefined;
  return !!network && network in SIMULATION_ENDPOINTS;
}

/** Price in thousandths of a dollar (integer arithmetic): per item, basic unit or simulation price. */
export function priceMilli(path: string, body: unknown, unitMilli: number, simulation = true): number {
  const itemMilli = (item: unknown) => (simulation && simulates(item) ? Math.max(unitMilli, Math.round(SIMULATION_PRICE * 1000)) : unitMilli);
  if (!path.endsWith("/batch")) return itemMilli(body);
  const reqs = Array.isArray((body as { requests?: unknown } | null)?.requests) ? (body as { requests: unknown[] }).requests.slice(0, 25) : [];
  return reqs.length ? reqs.reduce<number>((sum, r) => sum + itemMilli(r), 0) : unitMilli;
}

export function makePrice(unit: number, simulation = true): (ctx: HTTPRequestContext) => string {
  const unitMilli = Math.round(unit * 1000);
  return (ctx) => `$${(priceMilli(ctx.path, ctx.adapter.getBody?.(), unitMilli, simulation) / 1000).toFixed(3)}`;
}

export function buildAccepts(env: WorkerEnv): PaymentOption[] {
  const payToEvm = env.PAY_TO_EVM ?? "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  const payToSol = env.PAY_TO_SOL ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
  const simulation = env.SIMULATION !== "off";
  const evm = makePrice(UNIT_PRICE_EVM, simulation);
  const accepts: PaymentOption[] = [
    { scheme: "exact", network: BASE_MAINNET, payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:137", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:42161", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:43114", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:143", payTo: payToEvm, price: evm },
    { scheme: "exact", network: "eip155:1329", payTo: payToEvm, price: evm },
    { scheme: "exact", network: SOLANA_MAINNET, payTo: payToSol, price: makePrice(UNIT_PRICE_SOL, simulation) },
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

/**
 * A facilitator restricted to some networks: its /supported kinds are filtered, so the
 * resource server routes only those networks to it (routing = first facilitator, in
 * order, that supports the network).
 */
export function scopedFacilitator(inner: FacilitatorClient, allow: (network: string) => boolean): FacilitatorClient {
  return {
    verify: (payload, requirements) => inner.verify(payload, requirements),
    settle: (payload, requirements) => inner.settle(payload, requirements),
    getSupported: async () => {
      const supported = await inner.getSupported();
      return { ...supported, kinds: supported.kinds.filter((k) => allow(String(k.network))) };
    },
  };
}

/**
 * Mainnet facilitators, in routing order.
 * - PayAI for EVM: it settles at our $0.001 price. Dexter publishes gas-cost floors that
 *   are above $0.001 on Base, Polygon, Arbitrum and Avalanche (measured 2026-09-29:
 *   $0.0015–$0.0061), and it refuses anything below them.
 * - Dexter for Solana (floor ≈ $0.0013 < $0.002) and Monad (≈ $0.0003), and for any EVM
 *   network PayAI does not support.
 * `/status` reports each network's facilitator and published floor against the price.
 */
export function mainnetFacilitators(env: WorkerEnv): Array<{ name: string; client: FacilitatorClient }> {
  const payai = new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_PAYAI ?? DEFAULT_PAYAI_FACILITATOR });
  const dexter = new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_MAINNET ?? DEFAULT_MAINNET_FACILITATOR });
  return [
    { name: "payai", client: scopedFacilitator(payai, (n) => n.startsWith("eip155:")) },
    { name: "dexter", client: dexter },
  ];
}

export type PaymentRoute = { network: string; price_usd: number; facilitator: string | null; floor_usd: number | null; below_floor: boolean };

/** Which facilitator settles each accepted network, with its published floor (cached 10 min). */
let routingCache: { at: number; value: Promise<PaymentRoute[]> } | null = null;
export function paymentRouting(env: WorkerEnv, injected?: Array<{ name: string; client: FacilitatorClient }>): Promise<PaymentRoute[]> {
  if (!injected && routingCache && Date.now() - routingCache.at < 10 * 60 * 1000) return routingCache.value;
  const facilitators = injected ?? mainnetFacilitators(env);
  const value = (async () => {
    const supported = await Promise.all(facilitators.map((f) => f.client.getSupported().catch(() => ({ kinds: [] as Array<{ x402Version: number; scheme: string; network: string; extra?: Record<string, unknown> }> }))));
    return buildAccepts(env)
      .filter((a) => !String(a.network).includes("sepolia") && String(a.network) !== SOLANA_DEVNET)
      .map((a) => {
        const network = String(a.network);
        const price = String(a.network) === SOLANA_MAINNET ? UNIT_PRICE_SOL : UNIT_PRICE_EVM;
        const i = supported.findIndex((s) => s.kinds.some((k) => k.x402Version === 2 && k.scheme === "exact" && String(k.network) === network));
        const kind = i >= 0 ? supported[i]?.kinds.find((k) => k.x402Version === 2 && k.scheme === "exact" && String(k.network) === network) : undefined;
        const floorRaw = kind?.extra && (kind.extra as { paymentFloorAvailable?: unknown }).paymentFloorAvailable === true ? Number((kind.extra as { minPaymentAmountUsd?: unknown }).minPaymentAmountUsd) : NaN;
        const floor = Number.isFinite(floorRaw) ? floorRaw : null;
        return { network, price_usd: price, facilitator: i >= 0 ? (facilitators[i]?.name ?? null) : null, floor_usd: floor, below_floor: floor !== null && price < floor };
      });
  })();
  if (injected) return value;
  routingCache = { at: Date.now(), value };
  value.catch(() => {
    routingCache = null;
  });
  return value;
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
  const pricing: PricingInfo = { unitUsd: UNIT_PRICE_EVM.toFixed(3), ...(env.SIMULATION !== "off" ? { simulationUsd: SIMULATION_PRICE.toFixed(3) } : {}), networks: accepts.map((a) => String(a.network)) };
  const kitWatch = kitWatchLookup(env);
  const deps: HandlerDeps = { provider: new Provider({ host, keyPair: loadKeyPair(env), jev, onchain, feeds, simulator, contractIntel, kitWatch }), pricing };

  const facilitators: FacilitatorClient[] = [
    ...mainnetFacilitators(env).map((f) => f.client),
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

export async function handleProtected(request: Request, _env: WorkerEnv, stack: Stack, serve: (req: Request) => Promise<Response>): Promise<Response> {
  const path = new URL(request.url).pathname;
  // 1. Read and validate before any payment work: invalid input is never priced. The
  //    cap is in BYTES and is enforced while streaming, so an oversized body is never
  //    fully buffered.
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
  const replay = () => new Request(request.url, { method: "POST", headers: request.headers, body: text });

  // 2. Every evaluation is paid (x402 v2, PAYMENT-SIGNATURE), priced per item: $0.001
  //    ($0.002 on Solana), or $0.005 for an item whose transaction is simulated; a batch
  //    is the sum of its items. There is no free tier. Without a payment the response is
  //    the 402 challenge listing the accepted mainnet options.
  const ctx: HTTPRequestContext = {
    adapter: fetchAdapter(request, parsed),
    path,
    method: request.method,
    ...(request.headers.get("PAYMENT-SIGNATURE") ? { paymentHeader: request.headers.get("PAYMENT-SIGNATURE") as string } : {}),
  };
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest(ctx);
  } catch {
    return json(500, { error: "payment_processing_failed" });
  }
  // 3. Evaluate, then settle; the result is released only after settlement succeeds.
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

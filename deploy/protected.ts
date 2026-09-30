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
import { SOLANA_DEVNET, SOLANA_MAINNET } from "../src/chains.js";
import { BASE_MAINNET, formatUsd, makePrice, MICRO, MODEL_COST_USD, networkPrice, SIMULATION_PRICE } from "./pricing.js";
import { allChecked, fetchAdapter, json } from "./http-util.js";
import { creditToken, CREDIT_PRICING, packMicro, spendCredits } from "./credits.js";
import { cdpAuthHeaders, CDP_FACILITATOR_URL, CDP_FEE_USD } from "./cdp.js";
import { BATCH_DISCOVERY, REQUEST_EXAMPLE, RISK_CHECK_DISCOVERY, SERVICE_METADATA } from "./discovery.js";
import type { ThreatIntelFeeds } from "../src/threat-intel.js";
import { HTTPFacilitatorClient, x402ResourceServer, type FacilitatorClient } from "@x402/core/server";
import { x402HTTPResourceServer, type HTTPAdapter, type HTTPRequestContext, type HTTPProcessResult, type HTTPResponseInstructions, type PaymentOption, type RoutesConfig } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import type { WorkerEnv } from "./runtime.js";

export * from "./pricing.js";
export { fetchAdapter, json } from "./http-util.js";

export const PROTECTED = new Set(["/v1/risk-check", "/v1/risk-check/batch"]);
const DEFAULT_FACILITATOR = "https://x402.org/facilitator";
const DEFAULT_MAINNET_FACILITATOR = "https://x402.dexter.cash";
const DEFAULT_PAYAI_FACILITATOR = "https://facilitator.payai.network";
const BASE_SEPOLIA = "eip155:84532";
const MAX_BODY_BYTES = 64 * 1024;
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

/** Mainnet payment networks, in the order the 402 challenge lists them (Base first). */
export const MAINNET_NETWORKS = [BASE_MAINNET, "eip155:137", "eip155:42161", "eip155:43114", "eip155:143", "eip155:1329", SOLANA_MAINNET] as const;

export function buildAccepts(env: WorkerEnv, price: (network: string) => PaymentOption["price"] = (n) => makePrice(networkPrice(n), env.SIMULATION !== "off")): PaymentOption[] {
  const payToEvm = env.PAY_TO_EVM ?? "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  const payToSol = env.PAY_TO_SOL ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
  const payTo = (network: string) => (network.startsWith("solana:") ? payToSol : payToEvm);
  const option = (network: string): PaymentOption => ({ scheme: "exact", network: network as PaymentOption["network"], payTo: payTo(network), price: price(network) });
  const accepts: PaymentOption[] = MAINNET_NETWORKS.map(option);
  if (env.ENABLE_TESTNETS === "true") for (const network of [BASE_SEPOLIA, "eip155:421614", SOLANA_DEVNET]) accepts.push(option(network));
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

const TEN_MINUTES = 10 * 60 * 1000;

/** Shares a facilitator's /supported for 10 minutes between routing and stack initialization. */
function memoSupported(inner: FacilitatorClient): FacilitatorClient {
  let entry: { at: number; value: ReturnType<FacilitatorClient["getSupported"]> } | null = null;
  return {
    verify: (payload, requirements) => inner.verify(payload, requirements),
    settle: (payload, requirements) => inner.settle(payload, requirements),
    getSupported: () => {
      if (!entry || Date.now() - entry.at > TEN_MINUTES) {
        const value = inner.getSupported();
        entry = { at: Date.now(), value };
        value.catch(() => (entry = null));
      }
      return entry.value;
    },
  };
}

/**
 * PayAI's live fee per settlement (USD), for the transfer methods our payers use: EIP-3009
 * on EVM networks, a plain transfer on Solana (GET /pricing; the SDK's /supported parser
 * drops the `pricing` object).
 */
export async function payaiFees(url: string, doFetch: typeof fetch = (input, init) => fetch(input, init)): Promise<Map<string, number>> {
  const res = await doFetch(`${url}/pricing`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(3000) });
  if (!res.ok) throw new Error(`payai pricing: HTTP ${res.status}`);
  const body = (await res.json()) as { rates?: Array<{ network?: string; scheme?: string; transferMethod?: string; usd?: string }> };
  const fees = new Map<string, number>();
  for (const r of body.rates ?? []) {
    if (r.scheme !== "exact" || !r.network) continue;
    if (r.transferMethod !== (r.network.startsWith("eip155:") ? "eip3009" : "svm_transfer")) continue;
    const usd = Number(r.usd);
    if (Number.isFinite(usd) && usd >= 0) fees.set(r.network, usd);
  }
  return fees;
}

/**
 * A mainnet facilitator, and what settling one payment through it costs us: a per-network
 * table (`fees`), or one fee for every network it settles (`flatFee`). Unknown: null.
 */
export type FacilitatorEntry = { name: string; client: FacilitatorClient; fees?: (() => Promise<Map<string, number>>) | undefined; flatFee?: number | undefined };

const clientCache = new Map<string, FacilitatorClient>();
function facilitatorClient(url: string, key = url, auth?: ConstructorParameters<typeof HTTPFacilitatorClient>[0]): FacilitatorClient {
  let client = clientCache.get(key);
  if (!client) {
    client = memoSupported(new HTTPFacilitatorClient({ url, ...auth }));
    clientCache.set(key, client);
  }
  return client;
}

/**
 * Mainnet facilitators, in tie-break order: PayAI (fees from its live table), Dexter (no fee,
 * floors), and Coinbase CDP when its API key is configured ($0.001 a settlement after 1,000
 * free a month; the key authenticates every call).
 */
export function mainnetFacilitators(env: WorkerEnv): FacilitatorEntry[] {
  const payaiUrl = env.X402_FACILITATOR_URL_PAYAI ?? DEFAULT_PAYAI_FACILITATOR;
  let feeCache: { at: number; value: Promise<Map<string, number>> } | null = null;
  const fees = () => {
    if (!feeCache || Date.now() - feeCache.at > TEN_MINUTES) {
      const value = payaiFees(payaiUrl);
      feeCache = { at: Date.now(), value };
      value.catch(() => (feeCache = null));
    }
    return feeCache.value;
  };
  const entries: FacilitatorEntry[] = [
    { name: "payai", client: facilitatorClient(payaiUrl), fees },
    { name: "dexter", client: facilitatorClient(env.X402_FACILITATOR_URL_MAINNET ?? DEFAULT_MAINNET_FACILITATOR), flatFee: 0 },
  ];
  const cdp = cdpClient(env);
  if (cdp) entries.push({ name: "cdp", client: cdp, flatFee: CDP_FEE_USD });
  return entries;
}

/** The CDP facilitator client, when both parts of the API key are set (Worker secrets). */
function cdpClient(env: WorkerEnv): FacilitatorClient | null {
  const id = env.CDP_API_KEY_ID?.trim();
  const secret = env.CDP_API_KEY_SECRET;
  if (!id || !secret?.trim()) return null;
  const url = env.X402_FACILITATOR_URL_CDP ?? CDP_FACILITATOR_URL;
  return facilitatorClient(url, `cdp:${url}:${id}`, { url, createAuthHeaders: cdpAuthHeaders(id, secret) });
}

export type PaymentRoute = {
  network: string;
  price_usd: number;
  facilitator: string | null;
  /** eip3009 (gasless for any payer), permit2 (needs the payer's Permit2 allowance) or svm. */
  transfer_method: string | null;
  /** What settling one payment costs us; null when unknown. */
  fee_usd: number | null;
  floor_usd: number | null;
  below_floor: boolean;
  /** Price minus the settlement fee and one model call. */
  margin_usd: number | null;
  margin_pct: number | null;
};

type Kind = { x402Version: number; scheme: string; network: string; extra?: Record<string, unknown> };
type Candidate = { name: string; index: number; method: string; floor: number | null; fee: number | null; usable: boolean; compatible: boolean };

/**
 * The route for one network: a facilitator that accepts the price, that any payer can pay
 * through (Permit2 only as a last resort), then the cheapest to us, then configured order.
 */
export function chooseRoute(candidates: Candidate[]): Candidate | undefined {
  const cost = (c: Candidate) => c.fee ?? Number.MAX_VALUE;
  return [...candidates].sort((a, b) => Number(b.usable) - Number(a.usable) || Number(b.compatible) - Number(a.compatible) || cost(a) - cost(b) || a.index - b.index)[0];
}

function candidateFor(entry: FacilitatorEntry, index: number, kinds: Kind[], fees: Map<string, number> | null, network: string, price: number): Candidate | null {
  const kind = kinds.find((k) => k.x402Version === 2 && k.scheme === "exact" && String(k.network) === network);
  if (!kind) return null;
  const extra = kind.extra ?? {};
  const method = network.startsWith("eip155:") ? String(extra.assetTransferMethod ?? "eip3009") : "svm";
  const floorRaw = extra.paymentFloorAvailable === true ? Number(extra.minPaymentAmountUsd) : Number.NaN;
  const floor = Number.isFinite(floorRaw) ? floorRaw : null;
  const fee = fees ? (fees.get(network) ?? entry.flatFee ?? null) : null;
  return { name: entry.name, index, method, floor, fee, usable: floor === null || price >= floor, compatible: method !== "permit2" };
}

/** Which facilitator settles each mainnet network, at what cost and margin (cached 10 min). */
let routingCache: { at: number; value: Promise<PaymentRoute[]> } | null = null;
export function paymentRouting(env: WorkerEnv, injected?: FacilitatorEntry[]): Promise<PaymentRoute[]> {
  if (!injected && routingCache && Date.now() - routingCache.at < TEN_MINUTES) return routingCache.value;
  const facilitators = injected ?? mainnetFacilitators(env);
  const value = (async () => {
    const [supported, fees] = await Promise.all([
      Promise.all(facilitators.map((f) => f.client.getSupported().then((s) => s.kinds as Kind[]).catch(() => [] as Kind[]))),
      Promise.all(facilitators.map((f) => (f.fees ? f.fees().catch(() => null) : Promise.resolve(new Map<string, number>())))),
    ]);
    return MAINNET_NETWORKS.map((network): PaymentRoute => {
      const price = networkPrice(network);
      const candidates = facilitators.map((f, i) => candidateFor(f, i, supported[i] ?? [], fees[i] ?? null, network, price)).filter((c): c is Candidate => c !== null);
      const route = chooseRoute(candidates);
      const margin = route && route.fee !== null ? price - route.fee - MODEL_COST_USD : null;
      return {
        network,
        price_usd: price,
        facilitator: route?.name ?? null,
        transfer_method: route?.method ?? null,
        fee_usd: route?.fee ?? null,
        floor_usd: route?.floor ?? null,
        below_floor: !!route && !route.usable,
        margin_usd: margin === null ? null : Math.round(margin * MICRO) / MICRO,
        margin_pct: margin === null ? null : Math.round((margin / price) * 1000) / 10,
      };
    });
  })();
  if (injected) return value;
  routingCache = { at: Date.now(), value };
  value.catch(() => {
    routingCache = null;
  });
  return value;
}

/**
 * The resource server's facilitator list: each facilitator scoped to the networks routed
 * to it, first, then the default order (CDP when configured, then PayAI, for EVM; Dexter
 * for the rest), which also covers testnets and a routing table that could not be computed.
 */
export function routedFacilitators(entries: FacilitatorEntry[], routes: PaymentRoute[] | null): FacilitatorClient[] {
  const routed = routes ? entries.map((e) => scopedFacilitator(e.client, (n) => routes.some((r) => r.network === n && r.facilitator === e.name))) : [];
  const byName = new Map(entries.map((e) => [e.name, e.client]));
  const evm = (name: string) => {
    const client = byName.get(name);
    return client ? [scopedFacilitator(client, (n) => n.startsWith("eip155:"))] : [];
  };
  const dexter = byName.get("dexter");
  return [...routed, ...evm("cdp"), ...evm("payai"), ...(dexter ? [dexter] : [])];
}

/**
 * Each configured mainnet facilitator's reachability, the mainnet networks it offers and
 * the settlement signers it publishes (from its /supported, shared with routing for 10
 * minutes), so anyone can tell on-chain which facilitator settled a payment. Errors are
 * reduced to an HTTP status or "unreachable": an authenticated facilitator's key never
 * reaches /status.
 */
export async function facilitatorStatus(env: WorkerEnv, injected?: FacilitatorEntry[]): Promise<Array<{ name: string; ok: boolean; networks: string[]; signers?: string[]; error?: string }>> {
  const offered = new Set<string>(MAINNET_NETWORKS);
  return Promise.all(
    (injected ?? mainnetFacilitators(env)).map(async (f) => {
      try {
        const { kinds, signers } = await f.client.getSupported();
        const networks = [...new Set(kinds.filter((k) => k.x402Version === 2 && k.scheme === "exact").map((k) => String(k.network)))].filter((n) => offered.has(n));
        const published = [...new Set(Object.values(signers ?? {}).flat().filter((a) => typeof a === "string" && /^[0-9A-Za-z]{32,44}$|^0x[0-9a-fA-F]{40}$/.test(a)))].slice(0, 100);
        return { name: f.name, ok: true, networks, ...(published.length ? { signers: published } : {}) };
      } catch (err) {
        const status = /\((\d{3})\)/.exec(String(err))?.[1];
        return { name: f.name, ok: false, networks: [], error: status ? `HTTP ${status}` : "unreachable" };
      }
    }),
  );
}

function stackKey(env: WorkerEnv): string {
  return JSON.stringify([
    env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY, env.JEV_ATTEST_PUBLIC_JWK,
    env.PAY_TO_EVM, env.PAY_TO_SOL, env.X402_FACILITATOR_URL, env.X402_FACILITATOR_URL_MAINNET, env.X402_FACILITATOR_URL_PAYAI, env.X402_FACILITATOR_URL_CDP,
    env.CDP_API_KEY_ID ?? null, env.CDP_API_KEY_SECRET ? "cdp-secret" : null,
    env.ENABLE_TESTNETS, env.ONCHAIN, env.RPC_URLS, env.SOL_RPC_URL_MAINNET, env.SIMULATION, env.SIMULATION_RPC_URLS, env.CONTRACT_INTEL,
  ]);
}

export function buildStack(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>, routes: PaymentRoute[] | null = null): Stack {
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
  const plain = (usd: number) => formatUsd(Math.round(usd * 1_000_000)).slice(1);
  const pricing: PricingInfo = {
    unitUsd: plain(networkPrice(BASE_MAINNET)),
    ...(env.SIMULATION !== "off" ? { simulationUsd: plain(SIMULATION_PRICE) } : {}),
    networks: accepts.map((a) => String(a.network)),
    byNetwork: Object.fromEntries(accepts.map((a) => [String(a.network), plain(networkPrice(String(a.network)))])),
    ...(env.CREDITS ? { credits: CREDIT_PRICING } : {}),
  };
  const kitWatch = kitWatchLookup(env);
  const deps: HandlerDeps = { provider: new Provider({ host, keyPair: loadKeyPair(env), jev, onchain, feeds, simulator, contractIntel, kitWatch }), pricing };

  const facilitators: FacilitatorClient[] = [
    ...routedFacilitators(mainnetFacilitators(env), routes),
    ...(env.ENABLE_TESTNETS === "true" ? [new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR })] : []),
  ];
  const resourceServer = new x402ResourceServer(facilitators);
  resourceServer.register("eip155:*", new ExactEvmScheme());
  resourceServer.register(SOLANA_MAINNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL_MAINNET ?? "https://api.mainnet-beta.solana.com" }));
  if (env.ENABLE_TESTNETS === "true") {
    resourceServer.register(SOLANA_DEVNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL ?? "https://api.devnet.solana.com" }));
  }
  return { deps, http: new x402HTTPResourceServer(resourceServer, paidRoutes(env)) };
}

/**
 * The paid routes. Each carries the service metadata and, for the checks, the Bazaar
 * discovery declaration (deploy/discovery.ts): catalogs that settle a payment list the
 * endpoint with a callable example. A credit pack costs its face value on every network.
 */
export function paidRoutes(env: WorkerEnv): RoutesConfig {
  const accepts = buildAccepts(env);
  const packAccepts = buildAccepts(env, () => (ctx) => formatUsd(packMicro(ctx.adapter.getBody?.()) ?? 0));
  const service = { serviceName: SERVICE_METADATA.serviceName, tags: [...SERVICE_METADATA.tags], iconUrl: SERVICE_METADATA.iconUrl, mimeType: "application/json" };
  return {
    "POST /v1/risk-check": {
      accepts,
      ...service,
      description: "Check a counterparty before paying: OFAC SDN, phishing and drainer feeds, a live watch of drainer infrastructure, transaction simulation and injected-instruction analysis. Returns a score and a signed ES256 attestation.",
      extensions: RISK_CHECK_DISCOVERY,
    },
    "POST /v1/risk-check/batch": {
      accepts,
      ...service,
      description: "Up to 25 counterparty risk checks in one call, billed per item, each with a signed ES256 attestation.",
      extensions: BATCH_DISCOVERY,
    },
    ...(env.CREDITS
      ? { "POST /v1/credits": { accepts: packAccepts, ...service, description: "Prepaid credits for x402check: one payment buys a balance ($0.10-$100); each check then costs $0.001 ($0.005 simulated) with no payment round trip." } }
      : {}),
  };
}

/** What a GET (a browser, a curious developer) receives from a POST-only paid endpoint: how to call it. */
export function usageFor(path: string): Record<string, unknown> {
  const plain = (usd: number) => formatUsd(Math.round(usd * MICRO)).slice(1);
  return {
    error: "method_not_allowed",
    detail: `POST a JSON body to ${path}. Every check is paid with x402: from prepaid credits (Authorization: Bearer x402c_…) or per call (an unpaid POST returns 402 with the options).`,
    example: path.endsWith("/batch") ? { requests: [REQUEST_EXAMPLE] } : REQUEST_EXAMPLE,
    pricing: { credits_usd: CREDIT_PRICING.check_usd, per_call_from_usd: plain(networkPrice(BASE_MAINNET)), simulated_usd: plain(SIMULATION_PRICE), buy_credits: 'POST /v1/credits {"amount_usd": 1}' },
    docs: "https://x402check.xyz/#integrate",
    discovery: "https://x402check.xyz/.well-known/risk-check.json",
  };
}

export async function ensureStack(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>): Promise<Stack> {
  // The routing table (cached 10 min) decides the facilitator order; a slow or failed lookup
  // falls back to the default order, and the stack is rebuilt once the table changes.
  const routes = await Promise.race([paymentRouting(env).catch(() => null), new Promise<null>((r) => setTimeout(() => r(null), 4000))]);
  const key = JSON.stringify([stackKey(env), routes?.map((r) => [r.network, r.facilitator]) ?? null]);
  if (cached?.key === key) return cached.stack;
  if (pending?.key !== key) {
    const stack = buildStack(env, feeds, routes);
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

function instructionsToResponse(instr: HTTPResponseInstructions): Response {
  return new Response(typeof instr.body === "string" ? instr.body : JSON.stringify(instr.body), {
    status: instr.status,
    headers: instr.headers,
  });
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

  // Prepaid credits: `Authorization: Bearer x402c_…` debits the balance instead of paying per call.
  const token = creditToken(request);
  if (token) return spendCredits(_env, token, path, parsed, () => serve(replay()));
  if (request.headers.get("authorization")?.startsWith("Bearer ")) return json(401, { error: "invalid_credit_token" });

  // 2. Every evaluation is paid (x402 v2, PAYMENT-SIGNATURE), priced per item and per
  //    payment network (pricing.ts: $0.0035 on Base), or $0.005 for an item whose
  //    transaction is simulated when that is higher; a batch is the sum of its items.
  //    There is no free tier. Without a payment the response is the 402 challenge
  //    listing the accepted mainnet options.
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

import { createHash, createPublicKey } from "node:crypto";
import { generateKeyPair, signJws, verifyJws, type KeyPair } from "../src/jws.js";
import { Provider, PROVIDER_VERSION, type PricingInfo } from "../src/provider.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient, type JevLike } from "../src/jev.js";
import type { HandlerDeps } from "../src/handler.js";
import { validateBatch, validateRequest } from "../src/validate.js";
import { createOnchainLookup } from "../src/onchain.js";
import { createSimulator } from "../src/simulation.js";
import { createContractIntel } from "../src/contract-intel.js";
import { kitWatchLookup } from "./kit-watch.js";
import { SOLANA_DEVNET, SOLANA_MAINNET } from "../src/chains.js";
import { BASE_MAINNET, formatUsd, makePrice, MICRO, MODEL_COST_USD, networkPrice, SIMULATION_PRICE } from "./pricing.js";
import { allChecked, fetchAdapter, json, payerOf, readCapped, recordSettlement, sanctionedPayer, settlementReceipt } from "./http-util.js";
import { claimPayment, paymentId, paymentVersion } from "./payment-claims.js";
import { creditToken, CREDIT_PRICING, packMicro, spendCredits } from "./credits.js";
import { cdpAuthHeaders, CDP_FACILITATOR_URL, CDP_FEE_USD } from "./cdp.js";
import { BATCH_DISCOVERY, openApiDocument, REQUEST_EXAMPLE, RISK_CHECK_DISCOVERY, SERVICE_METADATA } from "./discovery.js";
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
/** Whether the attestation key can sign verdicts relying parties accept (the stack refuses paid work otherwise). */
export type AttestationKeyStatus = { ok: boolean; kid: string; thumbprint: string | null; reason?: string };

export type Stack = {
  deps: HandlerDeps;
  http: x402HTTPResourceServer;
  keyStatus: AttestationKeyStatus;
};

let cached: { key: string; stack: Stack } | null = null;
let pending: { key: string; promise: Promise<{ stack: Stack; ok: boolean }> } | null = null;

/** Production is any host other than a local one: there an ephemeral or mismatched key is refused. */
export function isProductionHost(env: WorkerEnv): boolean {
  const host = (env.PROVIDER_HOST ?? "x402check.xyz").replace(/:\d+$/, "");
  return !(host === "localhost" || host === "127.0.0.1" || host.endsWith(".localhost") || host.endsWith(".test"));
}

function thumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  return createHash("sha256").update(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`).digest("base64url");
}

/**
 * The attestation key, checked: both secrets present, the private key's public half equal to the
 * published JWK, and a canary that signs and verifies. In production a failure is reported (and
 * paid work refused, with no charge) instead of silently signing with an ephemeral key.
 */
export function loadKeyPair(env: WorkerEnv): { keyPair: KeyPair; status: AttestationKeyStatus } {
  const production = isProductionHost(env);
  if (!env.JEV_ATTEST_PRIVATE_KEY || !env.JEV_ATTEST_PUBLIC_JWK) {
    const keyPair = generateKeyPair("jev-attest-v1");
    const reason = "attestation secrets missing: an ephemeral key signs nothing relying parties accept";
    if (production) console.error(`attestation key: ${reason}`);
    return { keyPair, status: { ok: !production, kid: keyPair.publicJwk.kid, thumbprint: thumbprint(keyPair.publicJwk), ...(production ? { reason } : {}) } };
  }
  const privatePem = env.JEV_ATTEST_PRIVATE_KEY.replace(/\\n/g, "\n");
  let jwk: KeyPair["publicJwk"];
  try {
    jwk = JSON.parse(env.JEV_ATTEST_PUBLIC_JWK) as KeyPair["publicJwk"];
  } catch {
    const keyPair = generateKeyPair("jev-attest-v1");
    console.error("attestation key: JEV_ATTEST_PUBLIC_JWK is not JSON");
    return { keyPair, status: { ok: false, kid: keyPair.publicJwk.kid, thumbprint: null, reason: "JEV_ATTEST_PUBLIC_JWK is not JSON" } };
  }
  const keyPair: KeyPair = { privatePem, publicJwk: jwk };
  const fail = (reason: string) => {
    console.error(`attestation key: ${reason}`);
    return { keyPair, status: { ok: false, kid: String(jwk.kid ?? ""), thumbprint: null, reason } };
  };
  if (!(jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string" && typeof jwk.kid === "string" && jwk.kid)) return fail("JEV_ATTEST_PUBLIC_JWK is not an EC P-256 public key with a kid");
  try {
    const derived = createPublicKey(privatePem).export({ format: "jwk" }) as { crv?: string; x?: string; y?: string };
    if (derived.crv !== "P-256" || derived.x !== jwk.x || derived.y !== jwk.y) return fail("JEV_ATTEST_PRIVATE_KEY does not match JEV_ATTEST_PUBLIC_JWK");
    const now = Math.floor(Date.now() / 1000);
    const canary = signJws({ iss: "canary", sub: "canary", score: 0, tier: "low", iat: now, exp: now + 60 } as never, jwk.kid, privatePem);
    if (!verifyJws(canary, jwk)) return fail("a canary attestation did not verify against the published key");
  } catch (err) {
    return fail(`the attestation key could not be loaded (${String(err).slice(0, 80)})`);
  }
  return { keyPair, status: { ok: true, kid: jwk.kid, thumbprint: thumbprint(jwk) } };
}

/** Mainnet payment networks, in the order the 402 challenge lists them (Base first). */
export const MAINNET_NETWORKS = [BASE_MAINNET, "eip155:137", "eip155:42161", "eip155:43114", "eip155:143", "eip155:1329", SOLANA_MAINNET] as const;

/**
 * The payment options of the 402 challenge. With a routing table, only the networks that have a
 * live facilitator are offered (one facilitator's outage must not break every network), and a
 * network routed to a Permit2-only facilitator says so. Testnets never in production.
 */
export function buildAccepts(env: WorkerEnv, price: (network: string) => PaymentOption["price"] = (n) => makePrice(networkPrice(n), env.SIMULATION !== "off"), routes: PaymentRoute[] | null = null): PaymentOption[] {
  const payToEvm = env.PAY_TO_EVM ?? "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  const payToSol = env.PAY_TO_SOL ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
  const payTo = (network: string) => (network.startsWith("solana:") ? payToSol : payToEvm);
  const route = (network: string) => routes?.find((r) => r.network === network);
  const option = (network: string): PaymentOption => ({
    scheme: "exact",
    network: network as PaymentOption["network"],
    payTo: payTo(network),
    price: price(network),
    ...(route(network)?.transfer_method === "permit2" ? { extra: { assetTransferMethod: "permit2" } } : {}),
  });
  const live = routes ? MAINNET_NETWORKS.filter((n) => route(n)?.facilitator) : MAINNET_NETWORKS;
  // Every network down (or unknown): offer them all rather than none; payments then fail per network.
  const accepts: PaymentOption[] = (live.length ? live : MAINNET_NETWORKS).map(option);
  if (env.ENABLE_TESTNETS === "true") {
    if (isProductionHost(env)) console.error("ENABLE_TESTNETS is set on a production host: ignored (testnet USDC is free)");
    else for (const network of [BASE_SEPOLIA, "eip155:421614", SOLANA_DEVNET]) accepts.push(option(network));
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

const TEN_MINUTES = 10 * 60 * 1000;
/** A facilitator's /supported answers within this, or it counts as down for this build (a hung one must not stall every route). */
const SUPPORTED_DEADLINE_MS = 5000;
/** verify and settle wait longer: a settlement confirms on-chain, and a timeout there would charge without a verdict. */
const FACILITATOR_TIMEOUT_MS = 30_000;

function withDeadline<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([promise, new Promise<T>((_resolve, reject) => (timer = setTimeout(() => reject(new Error(`${what}: no answer within ${ms} ms`)), ms)))]).finally(() => clearTimeout(timer));
}

/** Shares a facilitator's /supported for 10 minutes between routing and stack initialization. */
function memoSupported(inner: FacilitatorClient): FacilitatorClient {
  let entry: { at: number; value: ReturnType<FacilitatorClient["getSupported"]> } | null = null;
  return {
    verify: (payload, requirements) => inner.verify(payload, requirements),
    settle: (payload, requirements) => inner.settle(payload, requirements),
    getSupported: () => {
      if (!entry || Date.now() - entry.at > TEN_MINUTES) {
        const value = withDeadline(inner.getSupported(), SUPPORTED_DEADLINE_MS, "facilitator /supported");
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
    client = memoSupported(new HTTPFacilitatorClient({ url, timeoutMs: FACILITATOR_TIMEOUT_MS, ...auth }));
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
  let degraded = false;
  const value = (async () => {
    const [supported, fees] = await Promise.all([
      Promise.all(
        facilitators.map((f) =>
          f.client
            .getSupported()
            .then((s) => s.kinds as Kind[])
            .catch((err: unknown) => {
              degraded = true;
              console.error(`facilitator ${f.name} /supported failed: ${String(err).slice(0, 160)}`);
              return [] as Kind[];
            }),
        ),
      ),
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
  const entry = { at: Date.now(), value };
  routingCache = entry;
  // A facilitator that failed is retried within a minute, not ten: recovery is picked up quickly.
  value.then(
    () => {
      if (degraded && routingCache === entry) entry.at = Date.now() - TEN_MINUTES + 45_000;
    },
    () => {
      if (routingCache === entry) routingCache = null;
    },
  );
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
    env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY, env.JEV_ATTEST_PUBLIC_JWK, env.JEV_ATTEST_NEXT_PUBLIC_JWK,
    env.PAY_TO_EVM, env.PAY_TO_SOL, env.X402_FACILITATOR_URL, env.X402_FACILITATOR_URL_MAINNET, env.X402_FACILITATOR_URL_PAYAI, env.X402_FACILITATOR_URL_CDP,
    env.CDP_API_KEY_ID ?? null, env.CDP_API_KEY_SECRET ? "cdp-secret" : null,
    env.ENABLE_TESTNETS, env.ONCHAIN, env.RPC_URLS, env.SOL_RPC_URL_MAINNET, env.SIMULATION, env.SIMULATION_RPC_URLS, env.CONTRACT_INTEL,
  ]);
}

let depsCache: { key: string; deps: HandlerDeps; keyStatus: AttestationKeyStatus } | null = null;

/**
 * The provider, its identity and pricing, without the payment stack: identity documents, the
 * site and discovery never wait for a facilitator. Cached per configuration and shared with the
 * payment stack (one Provider, one key).
 */
export function ensureDeps(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>): { deps: HandlerDeps; keyStatus: AttestationKeyStatus } {
  const key = stackKey(env);
  if (depsCache?.key !== key) depsCache = { key, ...buildDeps(env, feeds) };
  return depsCache;
}

/** The model backend the environment configures (TypeSafe direct, the AI Gateway, or none). */
export function jevFor(env: WorkerEnv): JevLike | null {
  return env.TYPESAFE_API_KEY ? new JevClient({ apiKey: env.TYPESAFE_API_KEY }) : env.AI_GATEWAY_API_KEY ? new GatewayJevClient() : null;
}

function buildDeps(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>): { deps: HandlerDeps; keyStatus: AttestationKeyStatus } {
  const host = env.PROVIDER_HOST ?? "x402check.xyz";
  const jev = jevFor(env);
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
  const { keyPair, status: keyStatus } = loadKeyPair(env);
  const deps: HandlerDeps = { provider: new Provider({ host, keyPair, jev, onchain, feeds, simulator, contractIntel, kitWatch }), pricing, ...nextKey(env) };
  return { deps, keyStatus };
}

export function buildStack(env: WorkerEnv, feeds?: () => Promise<ThreatIntelFeeds>, routes: PaymentRoute[] | null = null): Stack {
  const { deps, keyStatus } = ensureDeps(env, feeds);

  const facilitators: FacilitatorClient[] = [
    ...routedFacilitators(mainnetFacilitators(env), routes),
    ...(env.ENABLE_TESTNETS === "true" ? [new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR })] : []),
  ];
  const resourceServer = new x402ResourceServer(facilitators);
  resourceServer.register("eip155:*", new ExactEvmScheme());
  // api.mainnet-beta.solana.com refuses Worker egress (src/rpc.ts): publicnode serves it.
  resourceServer.register(SOLANA_MAINNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL_MAINNET ?? "https://solana-rpc.publicnode.com" }));
  if (env.ENABLE_TESTNETS === "true") {
    resourceServer.register(SOLANA_DEVNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL ?? "https://api.devnet.solana.com" }));
  }
  return { deps, http: new x402HTTPResourceServer(resourceServer, paidRoutes(env, routes)), keyStatus };
}

/** A next attestation key, published ahead of a rotation (JEV_ATTEST_NEXT_PUBLIC_JWK). */
function nextKey(env: WorkerEnv): { nextPublicJwk?: Record<string, unknown> } {
  if (!env.JEV_ATTEST_NEXT_PUBLIC_JWK) return {};
  try {
    const jwk = JSON.parse(env.JEV_ATTEST_NEXT_PUBLIC_JWK) as Record<string, unknown>;
    return jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string" && typeof jwk.kid === "string" ? { nextPublicJwk: jwk } : {};
  } catch {
    return {};
  }
}

/**
 * The paid routes. Each carries the service metadata and, for the checks, the Bazaar
 * discovery declaration (deploy/discovery.ts): catalogs that settle a payment list the
 * endpoint with a callable example. A credit pack costs its face value on every network.
 */
export function paidRoutes(env: WorkerEnv, routes: PaymentRoute[] | null = null): RoutesConfig {
  const accepts = buildAccepts(env, undefined, routes);
  const packAccepts = buildAccepts(env, () => (ctx) => formatUsd(packMicro(ctx.adapter.getBody?.()) ?? 0), routes);
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

/** The OpenAPI discovery document, priced from the live price table (per call: the cheapest to the dearest network). */
export function openApi(env: WorkerEnv): Record<string, unknown> {
  const plain = (usd: number) => formatUsd(Math.round(usd * MICRO)).slice(1);
  const perCall = buildAccepts(env).map((a) => networkPrice(String(a.network)));
  const min = Math.min(...perCall);
  const max = Math.max(...perCall, env.SIMULATION !== "off" ? SIMULATION_PRICE : 0);
  return openApiDocument(PROVIDER_VERSION, { minUsd: plain(min), maxUsd: plain(max), creditUsd: CREDIT_PRICING.check_usd, simulatedUsd: plain(SIMULATION_PRICE), basePerCallUsd: plain(networkPrice(BASE_MAINNET)) });
}

/** What a GET (a browser, a curious developer) receives from a POST-only paid endpoint: how to call it. */
export function usageFor(path: string): Record<string, unknown> {
  const plain = (usd: number) => formatUsd(Math.round(usd * MICRO)).slice(1);
  return {
    error: "method_not_allowed",
    detail: `POST a JSON body to ${path}. Every check is paid with x402: from prepaid credits (Authorization: Bearer x402c_…) or per call (an unpaid POST returns 402 with the options).`,
    example: path.endsWith("/batch") ? { requests: [REQUEST_EXAMPLE] } : REQUEST_EXAMPLE,
    pricing: {
      credits_usd: CREDIT_PRICING.check_usd,
      per_call_from_usd: plain(Math.min(...MAINNET_NETWORKS.map(networkPrice))),
      per_call_base_usd: plain(networkPrice(BASE_MAINNET)),
      simulated_usd: plain(SIMULATION_PRICE),
      buy_credits: 'POST /v1/credits {"amount_usd": 1}',
    },
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
        () => ({ stack, ok: true }),
        (err: unknown) => {
          console.error(`payment stack initialization failed: ${String(err).slice(0, 200)}`);
          return { stack, ok: false };
        },
      ),
    };
  }
  const current = pending;
  const { stack, ok } = await current.promise;
  // A stack whose facilitators could not be reached is used once, never cached: the next request retries.
  if (ok) cached = { key, stack };
  else if (pending === current) pending = null;
  return stack;
}

function instructionsToResponse(instr: HTTPResponseInstructions): Response {
  return new Response(typeof instr.body === "string" ? instr.body : JSON.stringify(instr.body), {
    status: instr.status,
    headers: instr.headers,
  });
}

export async function handleProtected(request: Request, _env: WorkerEnv, stack: Stack, serve: (req: Request) => Promise<Response>, ctx?: { waitUntil(promise: Promise<unknown>): void }): Promise<Response> {
  const path = new URL(request.url).pathname;
  // 0. A key that cannot sign verifiable attestations: no paid work at all (no charge).
  if (stack.keyStatus && !stack.keyStatus.ok) return json(503, { error: "attestation_key_unavailable", detail: "no charge: the provider cannot sign verifiable attestations right now" }, { "Retry-After": "60" });
  // 1. Read and validate before any payment work: invalid input is never priced. The
  //    cap is in BYTES and is enforced while streaming, so an oversized body is never
  //    fully buffered.
  const bytes = await readCapped(request, MAX_BODY_BYTES);
  if (!bytes) return json(413, { error: "body_too_large", max_bytes: MAX_BODY_BYTES });
  const text = new TextDecoder().decode(bytes);
  // A discovery probe (x402scan, AgentCash): an unpaid, unauthenticated request with no body
  // gets the 402 challenge for one item, so the endpoint shows as payable. A body that is
  // present but invalid still gets a 422 naming the field, and nothing unpaid is evaluated.
  if (text.trim() === "" && !request.headers.get("PAYMENT-SIGNATURE") && !request.headers.get("authorization")) {
    try {
      const probe = await stack.http.processHTTPRequest({ adapter: fetchAdapter(request, {}), path, method: request.method });
      if (probe.type === "payment-error") return instructionsToResponse(probe.response);
    } catch {
      return json(500, { error: "payment_processing_failed" });
    }
    return json(402, { error: "payment_required" });
  }
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
  if (token) return spendCredits(_env, token, path, parsed, () => serve(replay()), ctx);
  if (request.headers.get("authorization")?.startsWith("Bearer ")) return json(401, { error: "invalid_credit_token" });

  // 2. Every evaluation is paid (x402 v2, PAYMENT-SIGNATURE), priced per item and per
  //    payment network (pricing.ts: $0.0035 on Base), or $0.005 for an item whose
  //    transaction is simulated when that is higher; a batch is the sum of its items.
  //    There is no free tier. Without a payment the response is the 402 challenge
  //    listing the accepted mainnet options.
  // Only x402 v2 payments (what the challenge offers); anything else gets the v2 challenge.
  const header = request.headers.get("PAYMENT-SIGNATURE");
  const payment = header && paymentVersion(header) === 2 ? header : null;
  const httpCtx: HTTPRequestContext = {
    adapter: fetchAdapter(request, parsed),
    path,
    method: request.method,
    ...(payment ? { paymentHeader: payment } : {}),
  };
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest(httpCtx);
  } catch (err) {
    console.error(`payment processing failed on ${path}: ${String(err).slice(0, 200)}`);
    return json(500, { error: "payment_processing_failed" });
  }
  // 3. Evaluate, then settle; the result is released only after settlement succeeds.
  if (result.type === "payment-error") return instructionsToResponse(result.response);
  if (result.type === "no-payment-required") return json(402, { error: "payment_required" });
  // The payer is screened like any counterparty: no service is sold to an SDN-listed wallet.
  if (sanctionedPayer(payerOf(result.paymentPayload))) return json(403, { error: "payer_sanctioned", detail: "the paying wallet is on the OFAC SDN list; nothing was charged" });
  // Single use: one evaluation and one settlement per payment, however often it is sent.
  const claim = await claimPayment(_env, await paymentId(payment));
  if (!claim.claimed) {
    return claim.reason === "duplicate"
      ? json(409, { error: "payment_already_used", detail: "this payment was already presented; sign a new one" })
      : json(503, { error: "payment_claims_unavailable", detail: "no charge: retry shortly" }, { "Retry-After": "5" });
  }
  let res: Response;
  try {
    res = await serve(replay());
  } catch (err) {
    await claim.release();
    throw err;
  }
  if (res.status !== 200) {
    await claim.release();
    return res;
  }
  // Never charge for a verdict that was not produced: every result must be checked.
  if (!(await allChecked(res.clone()))) {
    await claim.release();
    return json(503, { error: "evaluation_unavailable", detail: "no charge: the evaluation could not be completed" }, { "Retry-After": "5" });
  }
  // Settle before releasing the result: a payload that verifies but cannot settle
  // (replayed authorization, funds moved between verify and settle) must not
  // receive a signed attestation.
  let reason = "settlement_failed";
  try {
    const settle = await stack.http.processSettlement(result.paymentPayload, result.paymentRequirements);
    if (settle.success) {
      await claim.settled();
      for (const [k, v] of Object.entries(settle.headers)) res.headers.set(k, v);
      const receipt = settlementReceipt(settle.headers);
      if (receipt) await recordSettlement(_env, { path, network: receipt.network, transaction: receipt.transaction });
      return res;
    }
    reason = settle.errorReason ?? reason;
  } catch (err) {
    console.error(`settlement failed on ${path}: ${String(err).slice(0, 200)}`);
  }
  await claim.release();
  console.warn(`settlement refused on ${path}: ${reason}`);
  return json(402, { error: "payment_settlement_failed" }, { "X-Payment-Error": reason });
}

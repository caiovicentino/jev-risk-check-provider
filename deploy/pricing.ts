import type { HTTPRequestContext } from "@x402/core/http";
import { normalizeChain, SOLANA_MAINNET } from "../src/chains.js";
import { parseSubject } from "../src/address.js";
import { SIMULATION_ENDPOINTS } from "../src/rpc.js";

// What an evaluation costs the payer, per payment network, and how a request is priced.
// Shared by the paywall (deploy/protected.ts) and prepaid credits (deploy/credits.ts).

export const BASE_MAINNET = "eip155:8453";

/**
 * Price per evaluation, by payment network (USD). The payer pays exactly this, and it
 * reaches our wallet in full; settling it costs us, separately:
 * - PayAI settles EVM payments with EIP-3009 (gasless for any payer) and, since
 *   2026-09-21, bills the receiving merchant the network's gas + 30% per settlement
 *   (Base ≈ $0.0023, Polygon ≈ $0.0049, Arbitrum ≈ $0.0066, Sei ≈ $0.0008, Avalanche
 *   ≈ $0.0001).
 * - Dexter sponsors gas and bills nothing, but it refuses payments below its floor
 *   (Solana ≈ $0.0013, Monad ≈ $0.0003). On EVM networks it settles through Permit2,
 *   which only payers with a Permit2 allowance, or a wallet that can sign the EIP-2612
 *   sponsoring extension, can use.
 * Each price clears the cost of the route it takes (paymentRouting). `/status` → payments
 * shows the live fee, floor and margin per network. Prepaid credits (deploy/credits.ts)
 * spread one settlement over many checks.
 */
export const NETWORK_PRICES: Readonly<Record<string, number>> = {
  [BASE_MAINNET]: 0.0035,
  "eip155:137": 0.007,
  "eip155:42161": 0.009,
  "eip155:43114": 0.001,
  "eip155:143": 0.001,
  "eip155:1329": 0.002,
  [SOLANA_MAINNET]: 0.002,
};
/** Testnet options (ENABLE_TESTNETS only): nominal. */
export const TESTNET_PRICE = 0.001;
/**
 * An evaluation that simulates a transaction (eth_simulateV1, classification of every
 * recipient and spender, code fingerprints through delegations and proxies): the most
 * valuable and most expensive layer. Charged only when the simulation can run, and never
 * below the network's own price.
 */
export const SIMULATION_PRICE = 0.005;
/** What one model (Jev) call costs us, measured: $0.0152 for 225 calls. */
export const MODEL_COST_USD = 0.00007;

export function networkPrice(network: string): number {
  return NETWORK_PRICES[network] ?? TESTNET_PRICE;
}

export const MICRO = 1_000_000;
/** USD to integer micro-dollars (USDC has 6 decimals). */
export function toMicro(usd: number): number {
  return Math.round(usd * MICRO);
}
/** "$0.0035", "$0.025", "$1.50": at least two decimals, and as many as the amount needs. */
export function formatUsd(micro: number): string {
  const [int, dec = ""] = (micro / MICRO).toFixed(6).replace(/0+$/, "").split(".");
  return `$${int}.${dec.padEnd(2, "0")}`;
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

/** Price in micro-dollars (integer arithmetic): per item, the unit price or, for an item that is simulated, the simulation price if higher. */
export function priceMicro(path: string, body: unknown, unitMicro: number, simulation = true): number {
  const itemMicro = (item: unknown) => (simulation && simulates(item) ? Math.max(unitMicro, toMicro(SIMULATION_PRICE)) : unitMicro);
  if (!path.endsWith("/batch")) return itemMicro(body);
  const reqs = Array.isArray((body as { requests?: unknown } | null)?.requests) ? (body as { requests: unknown[] }).requests.slice(0, 25) : [];
  return reqs.length ? reqs.reduce<number>((sum, r) => sum + itemMicro(r), 0) : unitMicro;
}

export function makePrice(unit: number, simulation = true): (ctx: HTTPRequestContext) => string {
  const unitMicro = toMicro(unit);
  return (ctx) => formatUsd(priceMicro(ctx.path, ctx.adapter.getBody?.(), unitMicro, simulation));
}

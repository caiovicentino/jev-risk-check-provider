// JSON-RPC endpoints with a fallback per chain, and a caller-side time budget shared
// between them: the primary gets most of it, the fallback whatever is left. Public
// RPCs rate-limit shared egress (Cloudflare) unpredictably, so one endpoint per
// chain is not enough for a fail-closed product.
import { SOLANA_MAINNET } from "./chains.js";

/** Public endpoints, primary first. The primaries serve JSON-RPC batches and eth_simulateV1. */
export const RPC_ENDPOINTS: Record<string, readonly string[]> = {
  "eip155:1": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"],
  "eip155:8453": ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
  "eip155:137": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"],
  "eip155:42161": ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"],
  "eip155:10": ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
  "eip155:43114": ["https://avalanche-c-chain-rpc.publicnode.com", "https://api.avax.network/ext/bc/C/rpc"],
  "eip155:56": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org"],
  // api.mainnet-beta.solana.com refuses Cloudflare Worker egress; publicnode serves it.
  [SOLANA_MAINNET]: ["https://solana-rpc.publicnode.com"],
};

/** Endpoints verified to serve eth_simulateV1 (Avalanche's do not; arb1.arbitrum.io does not). */
export const SIMULATION_ENDPOINTS: Record<string, readonly string[]> = {
  "eip155:1": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"],
  "eip155:8453": ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
  "eip155:137": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"],
  "eip155:42161": ["https://arbitrum-one-rpc.publicnode.com"],
  "eip155:10": ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
  "eip155:56": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org"],
};

/**
 * Block scanning for the kit watch (src/kit-watch-rpc.ts): full blocks in batches of 10,
 * about 20 GB a day for both chains. It runs on endpoints other than the ones that serve
 * evaluations, so the scan's volume can never rate-limit a paid check; the evaluation
 * primaries are the last fallback.
 */
export const SCAN_ENDPOINTS: Record<string, readonly string[]> = {
  "eip155:1": ["https://eth-mainnet.public.blastapi.io", "https://mainnet.gateway.tenderly.co", "https://ethereum-rpc.publicnode.com"],
  "eip155:8453": ["https://mainnet.base.org", "https://base-mainnet.public.blastapi.io", "https://base-rpc.publicnode.com"],
};

/**
 * The kit watch's code and storage reads (eth_getCode, eth_getStorageAt, in batches of up to 50),
 * healthiest first: each endpoint is sent only what the ones before it left unanswered. In the ops
 * review of 2026-10-02, publicnode and Base's official RPC answered 429 to 12–18% of calls and
 * dRPC 500 to 48% (its keyless plan refuses any batch of more than 3 calls), so BlastAPI leads.
 */
export const READ_ENDPOINTS: Record<string, readonly string[]> = {
  "eip155:1": ["https://eth-mainnet.public.blastapi.io", "https://ethereum-rpc.publicnode.com", "https://mainnet.gateway.tenderly.co", "https://eth.drpc.org"],
  "eip155:8453": ["https://base-mainnet.public.blastapi.io", "https://base-rpc.publicnode.com", "https://mainnet.base.org"],
};

/** Keyless tiers that refuse a whole JSON-RPC batch of more calls than this. */
export const BATCH_LIMITS: Record<string, number> = { "https://eth.drpc.org": 3, "https://mainnet.base.org": 10, "https://mainnet.gateway.tenderly.co": 10 };

/** An operator override (one URL) takes the primary slot; the defaults remain as fallbacks. */
export function endpointsFor(network: string, defaults: Record<string, readonly string[]>, override?: Record<string, string>): string[] {
  const list = [...(defaults[network] ?? [])];
  const o = override?.[network];
  return o ? [o, ...list.filter((u) => u !== o)] : list;
}

/**
 * POSTs `body` to each endpoint in turn until one answers with HTTP 200 and a
 * JSON-RPC response without a top-level error. The whole attempt is bounded by
 * `budgetMs`; the primary gets at most 60% of it when a fallback exists.
 */
export async function rpcWithFallback(urls: readonly string[], body: unknown, budgetMs: number, doFetch: typeof fetch, accept: (json: unknown) => boolean = () => true): Promise<unknown> {
  const deadline = Date.now() + budgetMs;
  let lastError: unknown = new Error("no rpc endpoint");
  for (let i = 0; i < urls.length; i++) {
    const remaining = deadline - Date.now();
    if (remaining < 150) break;
    const timeout = i < urls.length - 1 ? Math.min(remaining, Math.round(budgetMs * 0.6)) : remaining;
    try {
      const res = await doFetch(urls[i] as string, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeout) });
      if (!res.ok) throw new Error(`rpc http ${res.status}`);
      const json = (await res.json()) as unknown;
      // A rate-limit or method error on the whole call means: try the next endpoint.
      if (!Array.isArray(json) && json && typeof json === "object" && "error" in json && (json as { error?: unknown }).error !== undefined) throw new Error("rpc error");
      if (Array.isArray(body) && !Array.isArray(json)) throw new Error("rpc batch refused");
      if (!accept(json)) throw new Error("rpc answer rejected");
      return json;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

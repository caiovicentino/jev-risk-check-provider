// Contract reputation from public block explorers (Blockscout API v2, no key):
// whether a contract's source code is verified. Legitimate approval spenders
// (routers, aggregators, marketplaces, lending pools) are verified; drainer
// contracts often are not. A review-level signal only — never a block on its own.
// Timeboxed and cached; failures return undefined ("unknown"), never a verdict.

export const BLOCKSCOUT_HOSTS: Record<string, string> = {
  "eip155:1": "eth.blockscout.com",
  "eip155:8453": "base.blockscout.com",
  "eip155:137": "polygon.blockscout.com",
  "eip155:10": "optimism.blockscout.com",
  "eip155:42161": "arbitrum.blockscout.com",
};

/** verified: the explorer's answer · unavailable: the lookup failed on a supported chain (unknown, never "verified") · {}: unsupported. */
export type ContractIntel = (address: string, network: string | undefined) => Promise<{ verified?: boolean; unavailable?: boolean }>;

const TTL_MS = 24 * 60 * 60 * 1000;
// "Not verified" can change at any moment (a deployer verifies after the fact) and anyone
// could pre-warm it for a fresh contract: keep it briefly.
const UNVERIFIED_TTL_MS = 10 * 60 * 1000;

export function createContractIntel(opts: { hosts?: Record<string, string>; timeoutMs?: number; fetchImpl?: typeof fetch } = {}): ContractIntel {
  const hosts = { ...BLOCKSCOUT_HOSTS, ...(opts.hosts ?? {}) };
  const timeoutMs = opts.timeoutMs ?? 1500;
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const cache = new Map<string, { at: number; verified: boolean }>();
  return async (address, network) => {
    const host = network ? hosts[network] : undefined;
    if (!host || !/^0x[0-9a-fA-F]{40}$/.test(address)) return {};
    const key = `${network}|${address.toLowerCase()}`;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < (hit.verified ? TTL_MS : UNVERIFIED_TTL_MS)) return { verified: hit.verified };
    try {
      const res = await doFetch(`https://${host}/api/v2/addresses/${address}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
      // A 404 (not indexed yet: a fresh contract), a 429 or a 5xx is unknown, and not cached.
      if (!res.ok) return { unavailable: true };
      const body = (await res.json()) as { is_contract?: unknown; is_verified?: unknown; implementations?: unknown };
      if (body.is_contract !== true || typeof body.is_verified !== "boolean") return {};
      // A proxy the explorer resolved to a verified implementation runs verified code.
      const implVerified = Array.isArray(body.implementations) && body.implementations.some((i) => !!i && typeof (i as { name?: unknown }).name === "string" && ((i as { name: string }).name).length > 0);
      const verified = body.is_verified || implVerified;
      if (cache.size >= 5000) cache.delete(cache.keys().next().value as string);
      cache.set(key, { at: Date.now(), verified });
      return { verified };
    } catch {
      return { unavailable: true };
    }
  };
}

// Mirrors of the provider's input normalization (src/chains.ts, normalizeHost in
// src/domain-analysis.ts), so a client can compare what it sent with what was signed.

const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/** Chain aliases the API accepts, mapped to CAIP-2. */
export const CHAIN_ALIASES: ReadonlyMap<string, string> = new Map(
  Object.entries({
    ethereum: "eip155:1",
    eth: "eip155:1",
    "ethereum-mainnet": "eip155:1",
    base: "eip155:8453",
    "base-mainnet": "eip155:8453",
    polygon: "eip155:137",
    matic: "eip155:137",
    arbitrum: "eip155:42161",
    "arbitrum-one": "eip155:42161",
    optimism: "eip155:10",
    avalanche: "eip155:43114",
    avax: "eip155:43114",
    bsc: "eip155:56",
    bnb: "eip155:56",
    monad: "eip155:143",
    sei: "eip155:1329",
    "base-sepolia": "eip155:84532",
    "arbitrum-sepolia": "eip155:421614",
    sepolia: "eip155:11155111",
    solana: SOLANA_MAINNET,
    sol: SOLANA_MAINNET,
    "solana-mainnet": SOLANA_MAINNET,
    "solana-devnet": SOLANA_DEVNET,
    tron: "tron:0x2b6653dc",
    bitcoin: "bip122:000000000019d6689c085ae165831e93",
  }),
);

const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

/** A chain alias or CAIP-2 id → CAIP-2, as the API normalizes it. Null when not recognized. */
export function toCaip2(chain: string): string | null {
  if (typeof chain !== "string") return null;
  const v = chain.trim();
  if (!v || v.length > 64 || v !== chain) return null;
  const alias = CHAIN_ALIASES.get(v.toLowerCase());
  if (alias) return alias;
  return CAIP2.test(v) ? v : null;
}

/** A hostname or http(s) URL → the lowercase hostname the API analyzes and signs. Null when invalid. */
export function normalizeHost(input: string): string | null {
  if (typeof input !== "string") return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048 || /\s/.test(raw)) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  const host = url.hostname.replace(/\.$/, "").toLowerCase();
  if (!host || host.length > 253) return null;
  if (host.startsWith("[")) return host;
  if (!/^[a-z0-9.-]+$/.test(host) || host.split(".").some((label) => label.length === 0 || label.length > 63)) return null;
  return host;
}

// Chain identifiers accepted by the API. Anything else is rejected (422): the field
// reaches the model state, so it must be an identifier, never prose.
export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

const ALIASES = new Map<string, string>(Object.entries({
  ethereum: "eip155:1", eth: "eip155:1", "ethereum-mainnet": "eip155:1",
  base: "eip155:8453", "base-mainnet": "eip155:8453",
  polygon: "eip155:137", matic: "eip155:137",
  arbitrum: "eip155:42161", "arbitrum-one": "eip155:42161",
  optimism: "eip155:10", avalanche: "eip155:43114", avax: "eip155:43114",
  bsc: "eip155:56", bnb: "eip155:56", monad: "eip155:143", sei: "eip155:1329",
  "base-sepolia": "eip155:84532", "arbitrum-sepolia": "eip155:421614", sepolia: "eip155:11155111",
  solana: SOLANA_MAINNET, sol: SOLANA_MAINNET, "solana-mainnet": SOLANA_MAINNET, "solana-devnet": SOLANA_DEVNET,
  tron: "tron:0x2b6653dc", bitcoin: "bip122:000000000019d6689c085ae165831e93",
}));

const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

export type Chain = { input: string; caip2: string };

export function normalizeChain(raw: string): Chain | null {
  const v = raw.trim();
  if (!v || v.length > 64 || v !== raw) return null;
  const alias = ALIASES.get(v.toLowerCase()); // a Map: no prototype keys ("constructor", "__proto__")
  if (alias) return { input: v, caip2: alias };
  if (CAIP2.test(v) && knownCaip2(v)) return { input: v, caip2: v };
  return null;
}

const SOLANA_REFERENCES = new Set([SOLANA_MAINNET, SOLANA_DEVNET, "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"]);

/**
 * A CAIP-2 id the API can act on: an EVM chain id in its one canonical spelling ("eip155:08453"
 * would miss every table keyed by "eip155:8453" while x402 still pays on chain 8453), a known
 * Solana cluster, a Bitcoin-family genesis (bip122) or TRON. Anything else ("solana:mainnet",
 * "foo:bar") is refused: it would silently skip every chain-keyed check.
 */
function knownCaip2(v: string): boolean {
  if (v.startsWith("eip155:")) return /^eip155:(?:0|[1-9]\d{0,19})$/.test(v);
  if (v.startsWith("solana:")) return SOLANA_REFERENCES.has(v);
  if (v.startsWith("bip122:")) return /^bip122:[0-9a-f]{32}$/.test(v);
  if (v.startsWith("tron:")) return /^tron:0x[0-9a-f]{8}$/.test(v);
  return false;
}

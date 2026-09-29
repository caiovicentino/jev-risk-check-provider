import { SOLANA_MAINNET } from "./chains.js";
import type { Subject } from "./address.js";

// Provider-observed on-chain facts about the subject. Facts, not verdicts: an
// unused address is a weak risk factor (address poisoning, fresh drainer wallets),
// never proof of malice. Failures degrade to status "unavailable", never block.
export type OnchainEvidence = {
  status: "ok" | "unavailable" | "unsupported";
  network?: string;
  is_contract?: boolean;
  activity?: "none" | "some";
  /** EVM: outgoing tx count (nonce). Solana: recent signatures, capped at SOLANA_SIG_LIMIT. */
  tx_count?: number;
};

export const DEFAULT_RPC: Record<string, string> = {
  "eip155:1": "https://ethereum-rpc.publicnode.com",
  "eip155:8453": "https://mainnet.base.org",
  "eip155:137": "https://polygon-bor-rpc.publicnode.com",
  "eip155:42161": "https://arb1.arbitrum.io/rpc",
  "eip155:10": "https://mainnet.optimism.io",
  "eip155:43114": "https://api.avax.network/ext/bc/C/rpc",
  "eip155:56": "https://bsc-dataseed.bnbchain.org",
  [SOLANA_MAINNET]: "https://api.mainnet-beta.solana.com",
};

export const SOLANA_SIG_LIMIT = 25;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 5000;

export type OnchainLookup = (subject: Subject, network: string | undefined) => Promise<OnchainEvidence>;

type RpcResult = { id: number; result?: unknown; error?: unknown };

export function createOnchainLookup(opts: { rpc?: Record<string, string>; timeoutMs?: number; fetchImpl?: typeof fetch } = {}): OnchainLookup {
  const rpc = { ...DEFAULT_RPC, ...(opts.rpc ?? {}) };
  const timeoutMs = opts.timeoutMs ?? 1500;
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const cache = new Map<string, { at: number; value: OnchainEvidence }>();

  async function call(url: string, batch: Array<{ method: string; params: unknown[] }>): Promise<RpcResult[]> {
    const res = await doFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batch.map((b, i) => ({ jsonrpc: "2.0", id: i + 1, ...b }))),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`rpc http ${res.status}`);
    const body = (await res.json()) as RpcResult[] | RpcResult;
    const arr = Array.isArray(body) ? body : [body];
    if (arr.some((r) => r.error !== undefined)) throw new Error("rpc error");
    return arr.sort((a, b) => a.id - b.id);
  }

  async function evm(url: string, network: string, address: string): Promise<OnchainEvidence> {
    const [code, nonce, balance] = await call(url, [
      { method: "eth_getCode", params: [address, "latest"] },
      { method: "eth_getTransactionCount", params: [address, "latest"] },
      { method: "eth_getBalance", params: [address, "latest"] },
    ]);
    const codeHex = String(code?.result ?? "0x");
    // EIP-7702 delegated EOAs carry 0xef0100<target> designator code: still an EOA.
    const isContract = codeHex.length > 2 && !codeHex.toLowerCase().startsWith("0xef0100");
    const txCount = Number.parseInt(String(nonce?.result ?? "0x0"), 16);
    const bal = BigInt(String(balance?.result ?? "0x0"));
    if (!Number.isFinite(txCount)) throw new Error("bad nonce");
    return { status: "ok", network, is_contract: isContract, activity: !isContract && txCount === 0 && bal === 0n ? "none" : "some", tx_count: txCount };
  }

  async function solana(url: string, network: string, address: string): Promise<OnchainEvidence> {
    const [info, sigs] = await call(url, [
      { method: "getAccountInfo", params: [address, { encoding: "base64", dataSlice: { offset: 0, length: 0 } }] },
      { method: "getSignaturesForAddress", params: [address, { limit: SOLANA_SIG_LIMIT }] },
    ]);
    const value = (info?.result as { value?: { executable?: boolean } | null } | undefined)?.value ?? null;
    const signatures = Array.isArray(sigs?.result) ? sigs.result.length : 0;
    return { status: "ok", network, is_contract: value?.executable === true, activity: value === null && signatures === 0 ? "none" : "some", tx_count: signatures };
  }

  return async (subject, network) => {
    if (!network) return { status: "unsupported" };
    const url = rpc[network];
    const isEvm = network.startsWith("eip155:") && subject.format === "evm";
    const isSol = network === SOLANA_MAINNET && subject.format === "base58" && subject.address.length >= 32 && subject.address.length <= 44;
    if (!url || (!isEvm && !isSol)) return { status: "unsupported", network };
    const key = `${network}|${subject.canonical}`;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
    let value: OnchainEvidence;
    try {
      value = isEvm ? await evm(url, network, subject.canonical) : await solana(url, network, subject.address);
    } catch {
      return { status: "unavailable", network };
    }
    if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value as string);
    cache.set(key, { at: Date.now(), value });
    return value;
  };
}

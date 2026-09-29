import { SOLANA_MAINNET } from "./chains.js";
import { endpointsFor, rpcWithFallback, RPC_ENDPOINTS } from "./rpc.js";
import type { Subject } from "./address.js";
import { codeFacts, isContractCode, resolveIndirection, type CodeFacts } from "./code-fingerprint.js";

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
  /** Contract source verification (from a block explorer), when looked up. */
  verified?: boolean;
  /** EVM code classification and logic-code fingerprint (contracts and EIP-7702 delegated accounts). */
  code?: CodeFacts;
};

/** Primary endpoint per supported chain (fallbacks: src/rpc.ts). */
export const DEFAULT_RPC: Record<string, string> = Object.fromEntries(Object.entries(RPC_ENDPOINTS).map(([network, urls]) => [network, urls[0] as string]));

export const SOLANA_SIG_LIMIT = 25;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 5000;

export type OnchainLookup = (subject: Subject, network: string | undefined) => Promise<OnchainEvidence>;

type RpcResult = { id: number; result?: unknown; error?: unknown };

export function createOnchainLookup(opts: { rpc?: Record<string, string>; timeoutMs?: number; fetchImpl?: typeof fetch } = {}): OnchainLookup {
  const timeoutMs = opts.timeoutMs ?? 1500;
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const cache = new Map<string, { at: number; value: OnchainEvidence }>();

  async function call(urls: readonly string[], batch: Array<{ method: string; params: unknown[] }>): Promise<RpcResult[]> {
    // Every item must be answered; a per-item error (often a rate limit) moves on to the fallback.
    const complete = (json: unknown) => Array.isArray(json) && json.length === batch.length && json.every((r: RpcResult) => r && r.error === undefined && r.result !== undefined);
    const body = (await rpcWithFallback(urls, batch.map((b, i) => ({ jsonrpc: "2.0", id: i + 1, ...b })), timeoutMs, doFetch, complete)) as RpcResult[];
    return [...body].sort((a, b) => a.id - b.id);
  }

  async function evm(urls: readonly string[], network: string, address: string): Promise<OnchainEvidence> {
    const [code, nonce, balance] = await call(urls, [
      { method: "eth_getCode", params: [address, "latest"] },
      { method: "eth_getTransactionCount", params: [address, "latest"] },
      { method: "eth_getBalance", params: [address, "latest"] },
    ]);
    // EIP-7702 delegated EOAs carry 0xef0100<target> designator code: still an EOA.
    const facts = codeFacts(String(code?.result ?? "0x"));
    const isContract = isContractCode(facts);
    // Drainer code behind a 7702 delegation or a proxy is fingerprinted too.
    if (facts.kind === "delegated" || facts.kind === "delegating") {
      await resolveIndirection(new Map([[address, facts]]), async (requests) => (await call(urls, requests)).map((r) => r.result)).catch(() => undefined);
    }
    const txCount = Number.parseInt(String(nonce?.result ?? "0x0"), 16);
    const bal = BigInt(String(balance?.result ?? "0x0"));
    if (!Number.isFinite(txCount)) throw new Error("bad nonce");
    return { status: "ok", network, is_contract: isContract, activity: !isContract && txCount === 0 && bal === 0n ? "none" : "some", tx_count: txCount, ...(facts.kind !== "none" ? { code: facts } : {}) };
  }

  async function solana(urls: readonly string[], network: string, address: string): Promise<OnchainEvidence> {
    const [info, sigs] = await call(urls, [
      { method: "getAccountInfo", params: [address, { encoding: "base64", dataSlice: { offset: 0, length: 0 } }] },
      { method: "getSignaturesForAddress", params: [address, { limit: SOLANA_SIG_LIMIT }] },
    ]);
    const value = (info?.result as { value?: { executable?: boolean } | null } | undefined)?.value ?? null;
    const signatures = Array.isArray(sigs?.result) ? sigs.result.length : 0;
    return { status: "ok", network, is_contract: value?.executable === true, activity: value === null && signatures === 0 ? "none" : "some", tx_count: signatures };
  }

  return async (subject, network) => {
    if (!network) return { status: "unsupported" };
    const urls = endpointsFor(network, RPC_ENDPOINTS, opts.rpc);
    const isEvm = network.startsWith("eip155:") && subject.format === "evm";
    const isSol = network === SOLANA_MAINNET && subject.format === "base58" && subject.address.length >= 32 && subject.address.length <= 44;
    if (urls.length === 0 || (!isEvm && !isSol)) return { status: "unsupported", network };
    const key = `${network}|${subject.canonical}`;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
    let value: OnchainEvidence;
    try {
      value = isEvm ? await evm(urls, network, subject.canonical) : await solana(urls, network, subject.address);
    } catch {
      return { status: "unavailable", network };
    }
    if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value as string);
    cache.set(key, { at: Date.now(), value });
    return value;
  };
}

import { endpointsFor, rpcWithFallback, RPC_ENDPOINTS, SCAN_ENDPOINTS, SIMULATION_ENDPOINTS } from "./rpc.js";
import type { BatchCall } from "./code-fingerprint.js";
import type { RawBlock, SimulateCall, WatchChain } from "./kit-watch.js";

// JSON-RPC adapters for the kit watch, shared by the Worker cron and the Node scripts.

type RpcItem = { id: number; result?: unknown; error?: unknown };

export type KitWatchRpc = {
  call: BatchCall;
  simulate: SimulateCall;
  head: () => Promise<number>;
  /** Full blocks (transactions included), in order; a missing block throws (the cursor must not skip it). */
  blocks: (from: number, to: number) => Promise<RawBlock[]>;
};

export function kitWatchRpc(chain: WatchChain, opts: { fetchImpl?: typeof fetch; rpc?: Record<string, string>; scan?: Record<string, string>; timeoutMs?: number; batch?: number } = {}): KitWatchRpc {
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const urls = endpointsFor(chain, RPC_ENDPOINTS, opts.rpc);
  const simUrls = endpointsFor(chain, SIMULATION_ENDPOINTS, opts.rpc);
  const scanUrls = endpointsFor(chain, SCAN_ENDPOINTS, opts.scan);
  const timeoutMs = opts.timeoutMs ?? 20000;
  // Base's official RPC refuses batches over 10 calls; blocks are large anyway.
  const batchSize = opts.batch ?? 10;

  // `complete`: a batch with an unanswered item (often a per-item rate limit) moves on to the next endpoint.
  const batch = async (list: readonly string[], requests: Array<{ method: string; params: unknown[] }>, complete = false): Promise<RpcItem[]> => {
    const body = requests.map((r, i) => ({ jsonrpc: "2.0", id: i + 1, ...r }));
    const accept = (j: unknown) => Array.isArray(j) && (!complete || (j.length === requests.length && j.every((r: RpcItem) => r && r.error === undefined && r.result !== undefined && r.result !== null)));
    const json = (await rpcWithFallback(list, body, timeoutMs, doFetch, accept)) as RpcItem[];
    return [...json].sort((a, b) => a.id - b.id);
  };

  const call: BatchCall = async (requests) => {
    const out: unknown[] = [];
    for (let i = 0; i < requests.length; i += 50) {
      const chunk = requests.slice(i, i + 50);
      const res = await batch(urls, chunk);
      const byId = new Map(res.map((r) => [r.id, r.error === undefined ? r.result : undefined]));
      chunk.forEach((_, k) => out.push(byId.get(k + 1)));
    }
    return out;
  };

  const simulate: SimulateCall = async (c, stateOverrides) => {
    const body = { jsonrpc: "2.0", id: 1, method: "eth_simulateV1", params: [{ blockStateCalls: [{ stateOverrides, calls: [c] }], traceTransfers: true, validation: false }, "latest"] };
    const json = (await rpcWithFallback(simUrls, body, timeoutMs, doFetch)) as { result?: Array<{ calls?: Array<{ status?: string; logs?: Array<{ address: string; topics: string[]; data: string }> }> }> };
    return json.result?.[0]?.calls?.[0] ?? null;
  };

  const head = async (): Promise<number> => {
    const json = (await rpcWithFallback(scanUrls, { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }, timeoutMs, doFetch)) as { result?: string };
    const n = Number.parseInt(json.result ?? "", 16);
    if (!Number.isFinite(n)) throw new Error("bad block number");
    return n;
  };

  const blocks = async (from: number, to: number): Promise<RawBlock[]> => {
    const out: RawBlock[] = [];
    for (let n = from; n <= to; n += batchSize) {
      const numbers = Array.from({ length: Math.min(batchSize, to - n + 1) }, (_, i) => n + i);
      const res = await batch(scanUrls, numbers.map((b) => ({ method: "eth_getBlockByNumber", params: [`0x${b.toString(16)}`, true] })), true);
      numbers.forEach((b, i) => {
        const block = res[i]?.result as RawBlock | null | undefined;
        if (!block || !Array.isArray(block.transactions) || Number.parseInt(block.number, 16) !== b) throw new Error(`block ${b} unavailable`);
        out.push(block);
      });
    }
    return out;
  };

  return { call, simulate, head, blocks };
}

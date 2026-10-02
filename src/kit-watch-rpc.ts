import { BATCH_LIMITS, endpointsFor, READ_ENDPOINTS, rpcWithFallback, SCAN_ENDPOINTS, SIMULATION_ENDPOINTS } from "./rpc.js";
import type { BatchCall } from "./code-fingerprint.js";
import type { RawBlock, SimulateCall, WatchChain } from "./kit-watch.js";

// JSON-RPC adapters for the kit watch, shared by the Worker cron and the Node scripts.

type RpcItem = { id: number; result?: unknown; error?: unknown };
type RpcRequest = { method: string; params: unknown[] };

export type KitWatchRpc = {
  /** Batched reads in request order; an item no endpoint answered is undefined. */
  call: BatchCall;
  simulate: SimulateCall;
  head: () => Promise<number>;
  /** Full blocks (transactions included), in order; a missing block throws (the cursor must not skip it). */
  blocks: (from: number, to: number) => Promise<RawBlock[]>;
  /** The same, handed over batch by batch, so that each batch's bodies can be dropped once it is processed. */
  eachBlocks: (from: number, to: number, onBatch: (blocks: RawBlock[]) => void) => Promise<void>;
};

/** Reads per request. */
const READ_CHUNK = 50;
/** Requests one endpoint may get per chunk: a small-batch tier fills small holes only. */
const MAX_REQUESTS_PER_ENDPOINT = 4;
/**
 * Block JSON asked for per request. A parsed full block takes several times its JSON in memory and
 * the isolate has 128 MB, so the batch follows the size of the blocks just fetched.
 */
const BLOCK_BYTES_TARGET = 2_000_000;

/** One batch to one endpoint: each item's result in request order (undefined when unanswered) and the JSON's size; null when the call failed. */
async function postBatch(doFetch: typeof fetch, url: string, requests: readonly RpcRequest[], timeoutMs: number): Promise<{ results: unknown[]; bytes: number } | null> {
  try {
    const res = await doFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(requests.map((r, i) => ({ jsonrpc: "2.0", id: i + 1, ...r }))), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    const text = await res.text();
    const bytes = text.length;
    const json = JSON.parse(text) as unknown;
    if (!Array.isArray(json)) return null;
    const results: unknown[] = Array.from({ length: requests.length }, () => undefined);
    for (const item of json as RpcItem[]) {
      const k = typeof item?.id === "number" ? item.id - 1 : -1;
      if (k >= 0 && k < requests.length && item.error === undefined && item.result !== undefined && item.result !== null) results[k] = item.result;
    }
    return { results, bytes };
  } catch {
    return null;
  }
}

export function kitWatchRpc(chain: WatchChain, opts: { fetchImpl?: typeof fetch; rpc?: Record<string, string>; scan?: Record<string, string>; timeoutMs?: number; batch?: number } = {}): KitWatchRpc {
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const readUrls = endpointsFor(chain, READ_ENDPOINTS, opts.rpc);
  const simUrls = endpointsFor(chain, SIMULATION_ENDPOINTS, opts.rpc);
  const scanUrls = endpointsFor(chain, SCAN_ENDPOINTS, opts.scan);
  const timeoutMs = opts.timeoutMs ?? 20000;
  // Base's official RPC refuses batches over 10 calls.
  const maxBatch = opts.batch ?? 10;
  // The first request is small; later ones follow the measured block size.
  let blockBatch = Math.min(maxBatch, 2);

  // A read endpoint that failed or left holes is tried after the others for the rest of this run.
  const strikes = new Map<string, number>();
  const strike = (url: string) => strikes.set(url, (strikes.get(url) ?? 0) + 1);
  const byHealth = (urls: readonly string[]) => [...urls].sort((a, b) => (strikes.get(a) ?? 0) - (strikes.get(b) ?? 0));
  // Every request in a chunk shares one time budget; none takes more than 60% of it.
  const timeLeft = (deadline: number) => Math.min(deadline - Date.now(), Math.round(timeoutMs * 0.6));

  // A per-item rate limit or a refused batch loses nothing another endpoint can serve: each
  // endpoint, healthiest first, is sent only the items still unanswered.
  const call: BatchCall = async (requests) => {
    const out: unknown[] = Array.from({ length: requests.length }, () => undefined);
    for (let i = 0; i < requests.length; i += READ_CHUNK) {
      let missing = Array.from({ length: Math.min(READ_CHUNK, requests.length - i) }, (_, k) => i + k);
      const deadline = Date.now() + timeoutMs;
      for (const url of byHealth(readUrls)) {
        const size = BATCH_LIMITS[url] ?? READ_CHUNK;
        for (let s = 0, sent = 0; s < missing.length && sent < MAX_REQUESTS_PER_ENDPOINT && timeLeft(deadline) >= 150; s += size, sent++) {
          const part = missing.slice(s, s + size);
          const answer = await postBatch(doFetch, url, part.map((j) => requests[j] as RpcRequest), timeLeft(deadline));
          part.forEach((j, k) => {
            if (answer?.results[k] !== undefined) out[j] = answer.results[k];
          });
          if (!answer || part.some((j) => out[j] === undefined)) strike(url);
          if (!answer) break;
        }
        missing = missing.filter((j) => out[j] === undefined);
        if (!missing.length) break;
      }
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

  // Every block of the batch from one endpoint, or the next one. The scan's order is kept (not
  // reordered by health): the endpoints that serve evaluations stay the last fallback for its volume.
  const fetchBlocks = async (numbers: number[]): Promise<{ blocks: RawBlock[]; bytes: number }> => {
    const deadline = Date.now() + timeoutMs;
    for (const url of scanUrls) {
      if (timeLeft(deadline) < 150) break;
      if (numbers.length > (BATCH_LIMITS[url] ?? Number.POSITIVE_INFINITY)) continue;
      const answer = await postBatch(doFetch, url, numbers.map((b) => ({ method: "eth_getBlockByNumber", params: [`0x${b.toString(16)}`, true] })), timeLeft(deadline));
      const blocks = (answer?.results ?? []) as Array<RawBlock | undefined>;
      if (answer && numbers.every((b, i) => Array.isArray(blocks[i]?.transactions) && Number.parseInt(blocks[i]?.number ?? "", 16) === b)) return { blocks: blocks as RawBlock[], bytes: answer.bytes };
    }
    throw new Error(`blocks ${numbers[0]}-${numbers[numbers.length - 1]} unavailable`);
  };

  const eachBlocks = async (from: number, to: number, onBatch: (blocks: RawBlock[]) => void): Promise<void> => {
    for (let n = from; n <= to; ) {
      const numbers = Array.from({ length: Math.min(blockBatch, to - n + 1) }, (_, i) => n + i);
      const { blocks, bytes } = await fetchBlocks(numbers);
      onBatch(blocks);
      blockBatch = Math.max(1, Math.min(maxBatch, Math.floor((BLOCK_BYTES_TARGET * numbers.length) / Math.max(1, bytes))));
      n += numbers.length;
    }
  };

  const blocks = async (from: number, to: number): Promise<RawBlock[]> => {
    const out: RawBlock[] = [];
    await eachBlocks(from, to, (batch) => void out.push(...batch));
    return out;
  };

  return { call, simulate, head, blocks, eachBlocks };
}

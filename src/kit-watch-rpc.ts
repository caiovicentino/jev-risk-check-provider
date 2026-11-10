import { BATCH_LIMITS, endpointsFor, READ_ENDPOINTS, RPC_ENDPOINTS, rpcWithFallback, SCAN_ENDPOINTS, SIMULATION_ENDPOINTS } from "./rpc.js";
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
  /** Throws unless an endpoint other than the ones that named the last head serves this block. */
  confirm: (block: number) => Promise<void>;
  /** Full blocks (transactions included), in order; a missing block throws (the cursor must not skip it). */
  blocks: (from: number, to: number) => Promise<RawBlock[]>;
  /** The same, handed over batch by batch, so that each batch's bodies can be dropped once it is processed. */
  eachBlocks: (from: number, to: number, onBatch: (blocks: RawBlock[]) => void) => Promise<void>;
  /** The block batch the next request would ask for (follows the blocks' size): the cron keeps it for its next run. */
  blockBatchSize: () => number;
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

/**
 * One batch to one endpoint: each item's result in request order (undefined when unanswered) and the
 * JSON's size; null when the call failed, with the reason handed to `onFail` (an HTTP status, a
 * timeout, a body that is not a batch answer).
 */
async function postBatch(doFetch: typeof fetch, url: string, requests: readonly RpcRequest[], timeoutMs: number, onFail?: (reason: string) => void): Promise<{ results: unknown[]; bytes: number } | null> {
  const started = Date.now();
  try {
    const res = await doFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(requests.map((r, i) => ({ jsonrpc: "2.0", id: i + 1, ...r }))), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) {
      onFail?.(`HTTP ${res.status}`);
      return null;
    }
    const text = await res.text();
    const bytes = text.length;
    const json = JSON.parse(text) as unknown;
    if (!Array.isArray(json)) {
      onFail?.("not a batch answer");
      return null;
    }
    const results: unknown[] = Array.from({ length: requests.length }, () => undefined);
    for (const item of json as RpcItem[]) {
      const k = typeof item?.id === "number" ? item.id - 1 : -1;
      if (k >= 0 && k < requests.length && item.error === undefined && item.result !== undefined && item.result !== null) results[k] = item.result;
    }
    return { results, bytes };
  } catch (err) {
    onFail?.((err as { name?: string })?.name === "TimeoutError" ? `timeout after ${Date.now() - started} ms` : String((err as { name?: string })?.name ?? "error"));
    return null;
  }
}

export function kitWatchRpc(chain: WatchChain, opts: { fetchImpl?: typeof fetch; rpc?: Record<string, string>; scan?: Record<string, string>; scanEndpoints?: readonly string[]; timeoutMs?: number; batch?: number; blockBatch?: number | undefined; turn?: number; headGraceMs?: number } = {}): KitWatchRpc {
  const doFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const readUrls = endpointsFor(chain, READ_ENDPOINTS, opts.rpc);
  const simUrls = endpointsFor(chain, SIMULATION_ENDPOINTS, opts.rpc);
  // `scanEndpoints` replaces the list outright (tests); `scan` puts an operator's URL first.
  const scanUrls = opts.scanEndpoints ? [...opts.scanEndpoints] : endpointsFor(chain, SCAN_ENDPOINTS, opts.scan);
  const timeoutMs = opts.timeoutMs ?? 20000;
  // Base's official RPC refuses batches over 10 calls.
  const maxBatch = opts.batch ?? 10;
  // The first request is small unless an earlier run measured the blocks; later ones follow the measured size.
  let blockBatch = Math.min(maxBatch, Number.isSafeInteger(opts.blockBatch) && (opts.blockBatch as number) >= 1 ? (opts.blockBatch as number) : 2);

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

  // The head comes from the endpoints in the same rotation, so no one of them takes every request,
  // and it is the higher of two endpoints' answers: one that stopped following the chain (1rpc.io's
  // Base endpoint on 2026-11-05) can neither hold a run's scan back nor show its lag as 0. The two
  // get one request each, and one more of the rotation is asked only when one of them fails; the
  // rest, the evaluation endpoints last, only when neither answers (2026-11-09 review: the second
  // ask went down the whole list, so every rate-limited endpoint and the last fallback got a request
  // each run). Once a head is in hand, an endpoint still asked gets `headGraceMs` more, not the
  // whole timeout (the third one too: 2026-11-10 review). A stale endpoint that answers at once
  // therefore wins over a current one slower than the grace: that run scans nothing, and the next
  // asks two others. A head past the chain is caught where it could do harm: the cron skips ahead
  // only to a block that an endpoint other than the head's serves (`confirm`).
  const headGraceMs = opts.headGraceMs ?? 3000;
  // The endpoints whose answer was the last head (the highest).
  let headFrom: string[] = [];
  const head = async (): Promise<number> => {
    const order = scanOrder();
    const ask = async (url: string, budgetMs = timeoutMs): Promise<number> => {
      const json = (await rpcWithFallback([url], { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }, budgetMs, doFetch)) as { result?: string };
      const n = Number.parseInt(json.result ?? "", 16);
      if (!Number.isFinite(n)) throw new Error("bad block number");
      return n;
    };
    const answers: Array<{ url: string; n: number }> = [];
    const errors: unknown[] = [];
    const settle = async (urls: readonly string[]) => {
      let grace: ReturnType<typeof setTimeout> | undefined;
      await new Promise<void>((done) => {
        const wait = () => void (grace ??= setTimeout(done, headGraceMs));
        if (answers.length) wait();
        const asked = urls.map((url) =>
          ask(url).then(
            (n) => {
              answers.push({ url, n });
              wait();
            },
            (err: unknown) => void errors.push(err),
          ),
        );
        void Promise.allSettled(asked).then(() => done());
      });
      clearTimeout(grace);
    };
    await settle(order.slice(0, 2));
    const third = order[2];
    if (answers.length === 1 && errors.length === 1 && third !== undefined && rotating.includes(third)) await settle([third]);
    // Neither answered: the rest in order, the evaluation endpoints last, in one shared budget.
    const deadline = Date.now() + timeoutMs;
    for (const url of answers.length ? [] : order.slice(2)) {
      if (deadline - Date.now() < 150) break;
      const n = await ask(url, timeLeft(deadline)).catch((err: unknown) => void errors.push(err));
      if (n === undefined) continue;
      answers.push({ url, n });
      break;
    }
    if (!answers.length) throw errors[errors.length - 1];
    const max = Math.max(...answers.map((a) => a.n));
    headFrom = answers.filter((a) => a.n === max).map((a) => a.url);
    return max;
  };

  // An endpoint that serves another chain answers a head past this one, and that chain's blocks
  // too (2026-11-10 review): only another endpoint serving the block confirms the head.
  const confirm = async (n: number): Promise<void> => {
    const deadline = Date.now() + timeoutMs;
    const why: string[] = [];
    for (const url of [...rotating, ...lastResort].filter((u) => !headFrom.includes(u))) {
      const host = new URL(url).hostname;
      if (limited.has(url)) {
        why.push(`${host}: HTTP 429 earlier in this run`);
        continue;
      }
      if (deadline - Date.now() < 150) {
        why.push(`${host}: no time left`);
        break;
      }
      const answer = await postBatch(doFetch, url, [{ method: "eth_getBlockByNumber", params: [`0x${n.toString(16)}`, false] }], timeLeft(deadline), (reason) => {
        why.push(`${host}: ${reason}`);
        if (reason === "HTTP 429") limited.add(url);
      });
      if (Number.parseInt((answer?.results[0] as { number?: string } | undefined)?.number ?? "", 16) === n) return;
      if (answer) why.push(`${host}: no block ${n}`);
    }
    throw new Error(`block ${n} not served by an endpoint other than the head's (${why.join("; ") || "no other endpoint"})`);
  };

  // Every block of the batch from one endpoint, or the next one. Each batch starts at the next
  // endpoint that serves no evaluation, so the volume is spread; the endpoints that serve
  // evaluations stay the last fallback, in order (not reordered by health). A failure states what
  // each endpoint answered (host names only: an operator's URL may hold a key).
  const evaluation = new Set([...(RPC_ENDPOINTS[chain] ?? []), ...(SIMULATION_ENDPOINTS[chain] ?? [])]);
  const rotating = scanUrls.filter((u) => !evaluation.has(u));
  const lastResort = scanUrls.filter((u) => evaluation.has(u));
  // An endpoint that answered 429 is not asked for blocks again in this run: more requests would
  // only prolong its limit. When every endpoint is limited the scan stops, and the next run resumes.
  const limited = new Set<string>();
  // A batch rotates over the endpoints that accept its size (BATCH_LIMITS) and are not limited, so
  // turns stay even: one that cannot take it would hand its turn to the next, which then takes two.
  // The first turn is the caller's (the cron passes the minute): a run makes few requests, and
  // starting each at the same endpoint would give it every Ethereum batch.
  let turn = Math.max(0, Math.trunc(opts.turn ?? 0));
  const scanOrder = (size = 1): string[] => {
    const able = rotating.filter((u) => !limited.has(u) && size <= (BATCH_LIMITS[u] ?? Number.POSITIVE_INFINITY));
    const k = able.length ? turn++ % able.length : 0;
    return [...able.slice(k), ...able.slice(0, k), ...rotating.filter((u) => !able.includes(u)), ...lastResort];
  };
  const fetchBlocks = async (numbers: number[]): Promise<{ blocks: RawBlock[]; bytes: number }> => {
    const deadline = Date.now() + timeoutMs;
    const why: string[] = [];
    for (const url of scanOrder(numbers.length)) {
      const host = new URL(url).hostname;
      if (limited.has(url)) {
        why.push(`${host}: HTTP 429 earlier in this run`);
        continue;
      }
      if (timeLeft(deadline) < 150) {
        why.push(`${host}: no time left`);
        break;
      }
      if (numbers.length > (BATCH_LIMITS[url] ?? Number.POSITIVE_INFINITY)) continue;
      const answer = await postBatch(doFetch, url, numbers.map((b) => ({ method: "eth_getBlockByNumber", params: [`0x${b.toString(16)}`, true] })), timeLeft(deadline), (reason) => {
        why.push(`${host}: ${reason}`);
        if (reason === "HTTP 429") limited.add(url);
      });
      const blocks = (answer?.results ?? []) as Array<RawBlock | undefined>;
      if (answer && numbers.every((b, i) => Array.isArray(blocks[i]?.transactions) && Number.parseInt(blocks[i]?.number ?? "", 16) === b)) return { blocks: blocks as RawBlock[], bytes: answer.bytes };
      if (answer) why.push(`${host}: incomplete`);
    }
    throw new Error(`blocks ${numbers[0]}-${numbers[numbers.length - 1]} unavailable (${why.join("; ")})`);
  };

  // A batch no endpoint served in time is split: smaller requests get through where large ones do
  // not (a cron placed far from the RPCs downloads slowly), and the batch stays at most that size for
  // the rest of the run. A single block no endpoint serves ends the fetch: the cursor must not skip it.
  let ceiling = maxBatch;
  const eachBlocks = async (from: number, to: number, onBatch: (blocks: RawBlock[]) => void): Promise<void> => {
    for (let n = from; n <= to; ) {
      const numbers = Array.from({ length: Math.min(blockBatch, to - n + 1) }, (_, i) => n + i);
      let fetched: { blocks: RawBlock[]; bytes: number };
      try {
        fetched = await fetchBlocks(numbers);
      } catch (err) {
        // A single block, or every endpoint rate-limited: a smaller request would fare no better.
        if (numbers.length === 1 || scanUrls.every((u) => limited.has(u))) throw err;
        ceiling = Math.max(1, Math.floor(numbers.length / 2));
        blockBatch = ceiling;
        continue;
      }
      onBatch(fetched.blocks);
      blockBatch = Math.max(1, Math.min(ceiling, Math.floor((BLOCK_BYTES_TARGET * numbers.length) / Math.max(1, fetched.bytes))));
      n += numbers.length;
    }
  };

  const blocks = async (from: number, to: number): Promise<RawBlock[]> => {
    const out: RawBlock[] = [];
    await eachBlocks(from, to, (batch) => void out.push(...batch));
    return out;
  };

  return { call, simulate, head, confirm, blocks, eachBlocks, blockBatchSize: () => blockBatch };
}

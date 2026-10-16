// Kit watch reads (provider 0.6.2). A read one endpoint leaves unanswered goes to the next one;
// a read that still fails is queued and evaluated on a later run with its original block; the
// signed coverage clock states the reads still queued and every hole; KV writes per run and per
// day stay bounded, and blocks are fetched in batches sized by their JSON.
import { test } from "node:test";
import assert from "node:assert";
import { privateKeyToAccount } from "viem/accounts";
import { codeFacts } from "../src/code-fingerprint.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import { addBlocks, indexFamilies, MAX_AUTHORIZATIONS_PER_SCAN, mergeEntries, newActivity, rescanPending, scanActivity, scanBlocks, settledDelegates, type DelegateVerdict, type Family, type PendingRead, type RawAuthorization, type RawBlock, type ScanDeps, type SimulateCall, type WatchEntry } from "../src/kit-watch.js";
import { COVERAGE_V, coverageOf, DAILY_WRITE_BUDGET, kitWatchStatus, KW, LEASE_MS, LEGACY_DROPPED_READS, PENDING_MAX, runKitWatch, type ChainStats, type KitWatchStats } from "../deploy/kit-watch.js";
import type { KVNamespace } from "../deploy/runtime.js";

const hex20 = (n: number) => n.toString(16).padStart(40, "0");
const addr = (n: number) => `0x${hex20(n)}`;
const body = "63aabbccdd14".repeat(20);
const kitCode = (a: number, immutable: number, tail = "00") => `0x6080604052` + `73${hex20(a)}50` + `7f${immutable.toString(16).padStart(64, "0")}50` + body + tail;
const POISONER = kitCode(0x50, 1);
const DRAINER = kitCode(0x60, 2, "0000");
const fam = (id: string, cls: Family["class"], code: string): Family => {
  const f = codeFacts(code);
  return { id, class: cls, exact: [f.fingerprint as string], skeleton: [f.skeleton as string], sources: ["test"] };
};
// DRAINER matches this family by template (immutables and hard-coded addresses masked).
const KIT = fam("kit-y", "drainer_kit", kitCode(0x61, 98, "0000"));
const DEPLOYER = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0";
const KIT_ADDRESS = "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"; // DEPLOYER's CREATE at nonce 0
const T = Date.UTC(2026, 9, 2, 12, 0, 0);

const signer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
async function auth(delegate: string): Promise<RawAuthorization> {
  const a = await signer.signAuthorization({ address: delegate as `0x${string}`, chainId: 1, nonce: 0 });
  return { chainId: "0x1", address: delegate, nonce: "0x0", yParity: `0x${(a.yParity ?? 0).toString(16)}`, r: a.r, s: a.s };
}

type Reads = Array<{ method: string; params: unknown[] }>;
const reading = (code: Record<string, string>) => async (reqs: Reads) => reqs.map((r) => (r.method === "eth_getCode" ? (code[r.params[0] as string] ?? "0x") : undefined));
const unreadable = async (reqs: Reads) => reqs.map(() => undefined);
const noSim: SimulateCall = async () => null;
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const topic = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;
/** Whatever is sent to the account is passed on in full. */
const forwarding: SimulateCall = async (c) => ({
  status: "0x1",
  logs: [
    { address: NATIVE, topics: [TRANSFER, topic(c.from), topic(c.to)], data: `0x${BigInt(c.value).toString(16)}` },
    { address: NATIVE, topics: [TRANSFER, topic(c.to), topic(addr(0xde))], data: `0x${BigInt(c.value).toString(16)}` },
  ],
});

// --- RPC: reads and blocks -----------------------------------------------------------

type Req = { id: number; method: string; params: unknown[] };
const host = (url: string) => new URL(url).hostname;

test("code reads: what one endpoint leaves unanswered goes to the next, healthiest first, in bounded requests", async () => {
  const sent: Array<[string, number]> = [];
  // BlastAPI rate-limits every other item of a batch; publicnode answers everything.
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req[];
    sent.push([host(url), req.length]);
    const limited = url.includes("blastapi");
    return new Response(JSON.stringify(req.map((r) => (limited && r.id % 2 === 0 ? { jsonrpc: "2.0", id: r.id, error: { code: -32005, message: "rate limited" } } : { jsonrpc: "2.0", id: r.id, result: "0x60" }))));
  }) as unknown as typeof fetch;
  const rpc = kitWatchRpc("eip155:1", { fetchImpl });
  const out = await rpc.call(Array.from({ length: 60 }, (_, i) => ({ method: "eth_getCode", params: [addr(i + 1), "latest"] })));
  assert.equal(out.filter((v) => v === "0x60").length, 60, "no read is lost to a per-item rate limit");
  // The first chunk's holes go to publicnode; the second chunk goes there first (BlastAPI left holes).
  assert.deepEqual(sent, [["eth-mainnet.public.blastapi.io", 50], ["ethereum-rpc.publicnode.com", 25], ["ethereum-rpc.publicnode.com", 10]]);

  // Every endpoint failing: a keyless tier's batch limit is respected, and each endpoint gets a few requests at most.
  const tries: Array<[string, number]> = [];
  const failing = (async (url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req[];
    tries.push([host(url), req.length]);
    if (url.includes("drpc") && req.length <= 3) return new Response(JSON.stringify(req.map((r) => ({ jsonrpc: "2.0", id: r.id, result: "0x61" }))));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32005, message: "rate limit exceeded" } }), { status: 429 });
  }) as unknown as typeof fetch;
  const partial = await kitWatchRpc("eip155:1", { fetchImpl: failing }).call(Array.from({ length: 20 }, (_, i) => ({ method: "eth_getCode", params: [addr(i + 1), "latest"] })));
  assert.equal(partial.filter((v) => v === "0x61").length, 12, "dRPC fills 4 batches of 3");
  assert.equal(partial.filter((v) => v === undefined).length, 8, "what no endpoint answered stays undefined");
  assert.deepEqual(tries, [["eth-mainnet.public.blastapi.io", 20], ["ethereum-rpc.publicnode.com", 20], ["mainnet.gateway.tenderly.co", 10], ["eth.drpc.org", 3], ["eth.drpc.org", 3], ["eth.drpc.org", 3], ["eth.drpc.org", 3]]);
});

// Three scan endpoints (two that serve no evaluation, then publicnode, which does): the sequences below are exact.
const ETH_SCAN = ["https://eth-mainnet.public.blastapi.io", "https://mainnet.gateway.tenderly.co", "https://ethereum-rpc.publicnode.com"];
test("blocks: batches follow the blocks' JSON size, and each batch is handed over before the next is fetched", async () => {
  const events: string[] = [];
  let pad = "ab".repeat(400_000); // ~800 KB of calldata per block
  let missingOnce = true;
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req[];
    events.push(`fetch ${req.length}${url.includes("blastapi") ? "" : ` ${host(url)}`}`);
    // The first endpoint once leaves a block out: the batch goes to the next one, whole.
    if (missingOnce && url.includes("blastapi")) {
      missingOnce = false;
      return new Response(JSON.stringify(req.map((r) => ({ jsonrpc: "2.0", id: r.id, result: null }))));
    }
    return new Response(JSON.stringify(req.map((r) => ({ jsonrpc: "2.0", id: r.id, result: { number: r.params[0], timestamp: "0x1", transactions: [{ hash: "0x01", from: DEPLOYER, to: addr(1), nonce: "0x5", input: `0x${pad}` }] } }))));
  }) as unknown as typeof fetch;
  const rpc = kitWatchRpc("eip155:1", { fetchImpl, scanEndpoints: ETH_SCAN });
  const got: number[] = [];
  await rpc.eachBlocks(100, 109, (blocks) => {
    events.push(`hand ${blocks.length}`);
    got.push(...blocks.map((b) => Number.parseInt(b.number, 16)));
  });
  assert.deepEqual(got, Array.from({ length: 10 }, (_, i) => 100 + i), "every block, in order");
  // 2 blocks of ~800 KB fill the 2 MB a request asks for. The incomplete batch is fetched whole from
  // the next endpoint. Batches alternate between the endpoints that serve no evaluation (BlastAPI,
  // Tenderly): publicnode, which serves evaluations, is only the last fallback and is never reached.
  const T_ = "mainnet.gateway.tenderly.co";
  assert.deepEqual(events, ["fetch 2", `fetch 2 ${T_}`, "hand 2", `fetch 2 ${T_}`, "hand 2", "fetch 2", "hand 2", `fetch 2 ${T_}`, "hand 2", "fetch 2", "hand 2"]);
  // Small blocks grow the batch up to the endpoints' limit of 10.
  pad = "";
  events.length = 0;
  assert.equal((await rpc.blocks(200, 219)).length, 20);
  assert.deepEqual(events, [`fetch 2 ${T_}`, "fetch 10", `fetch 8 ${T_}`]);
});

test("blocks: a batch no endpoint serves is split, and stays that small for the run; a single block that fails says why per endpoint", async () => {
  const sizes: number[] = [];
  // Every endpoint refuses a request for more than 2 blocks (too large, or cut off by the timeout).
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req[];
    sizes.push(req.length);
    if (req.length > 2) return new Response("too large", { status: 413 });
    return new Response(JSON.stringify(req.map((r) => ({ jsonrpc: "2.0", id: r.id, result: { number: r.params[0], timestamp: "0x1", transactions: [] } }))));
  }) as unknown as typeof fetch;
  const rpc = kitWatchRpc("eip155:1", { fetchImpl, blockBatch: 7, scanEndpoints: ETH_SCAN });
  const got: number[] = [];
  await rpc.eachBlocks(100, 109, (blocks) => void got.push(...blocks.map((b) => Number.parseInt(b.number, 16))));
  assert.deepEqual(got, Array.from({ length: 10 }, (_, i) => 100 + i), "every block, in order");
  assert.deepEqual(sizes, [7, 7, 7, 3, 3, 3, ...Array.from({ length: 10 }, () => 1)], "7 fails on all three endpoints, then 3; single blocks get through, and the batch does not grow back");
  assert.equal(rpc.blockBatchSize(), 1, "the next run starts at the size that worked");

  const down = (async (url: string) => (url.includes("tenderly") ? new Response("[]") : new Response("busy", { status: 503 }))) as unknown as typeof fetch;
  await assert.rejects(kitWatchRpc("eip155:1", { fetchImpl: down, blockBatch: 1, scanEndpoints: ETH_SCAN }).eachBlocks(100, 100, () => undefined), (err: Error) => {
    assert.match(err.message, /^blocks 100-100 unavailable \(eth-mainnet\.public\.blastapi\.io: HTTP 503; mainnet\.gateway\.tenderly\.co: incomplete; ethereum-rpc\.publicnode\.com: HTTP 503\)$/);
    return true;
  });
});

// --- scan: reads that fail are handed back ------------------------------------------

test("scan: a creation whose code cannot be read is handed back, then evaluated with its original block, transaction and time", async () => {
  const families = indexFamilies({ updated_at: "", families: [KIT] });
  const block: RawBlock = { number: "0x20", timestamp: "0x6400", transactions: [{ hash: "0xc1", from: DEPLOYER, to: null, nonce: "0x0" }] };
  const deps = (call: ScanDeps["call"], now: number): ScanDeps => ({ chain: "eip155:1", call, simulate: noSim, families, delegates: new Map(), now: () => now });
  const first = await scanBlocks([block], deps(unreadable, 2_000_000));
  assert.equal(first.entries.length, 0, "unknown code is never taken for no code");
  assert.equal(first.stats.degraded, 1);
  assert.deepEqual(first.pending, [{ creation: { address: KIT_ADDRESS, deployer: DEPLOYER, tx: "0xc1", block: 0x20 }, t: 0x6400, q: 2_000_000 }]);
  // Still unreadable later: handed back again, with the time it was first queued.
  assert.deepEqual((await rescanPending(first.pending, deps(unreadable, 2_000_060))).pending, first.pending);
  // Read later: the entries an on-time read would have made.
  const later = await rescanPending(first.pending, deps(reading({ [KIT_ADDRESS]: DRAINER }), 2_000_600));
  assert.deepEqual(later.pending, []);
  const merged = mergeEntries(later.entries);
  assert.deepEqual(merged.get(KIT_ADDRESS), { k: "drainer_kit_contract", c: "eip155:1", f: "kit-y", t: 0x6400, b: 0x20, x: "0xc1" });
  assert.deepEqual(merged.get(DEPLOYER), { k: "drainer_kit_deployer", c: "eip155:1", f: "kit-y", t: 0x6400, b: 0x20, x: "0xc1", d: KIT_ADDRESS });
});

test("scan: an authorization whose delegate or authority cannot be read waits, then flags as it would have on time", async () => {
  const dPoison = addr(0xd0);
  const me = signer.address.toLowerCase();
  const families = indexFamilies({ updated_at: "", families: [fam("poisoner-x", "poisoner", kitCode(0x51, 99))] });
  const block: RawBlock = { number: "0x30", timestamp: "0x7000", transactions: [{ hash: "0xa1", from: me, to: dPoison, nonce: "0x0", type: "0x4", authorizationList: [await auth(dPoison)] }] };
  const delegates = new Map<string, DelegateVerdict>();
  const deps = (call: ScanDeps["call"]): ScanDeps => ({ chain: "eip155:1", call, simulate: noSim, families, delegates, now: () => 3_000_000 });
  // The delegate cannot be read: no verdict is cached, and the authorization waits.
  const first = await scanBlocks([block], deps(unreadable));
  assert.equal(delegates.size, 0);
  assert.deepEqual(first.pending.map((p) => [p.authorization?.tx, p.authorization?.block, p.t, p.q]), [["0xa1", 0x30, 0x7000, 3_000_000]]);
  // The delegate reads (a poisoner), the authority does not: the authorization still waits.
  const second = await rescanPending(first.pending, deps(async (reqs) => reqs.map((r) => (r.params[0] === dPoison ? POISONER : undefined))));
  assert.equal(delegates.get(dPoison)?.class, "poisoner");
  assert.deepEqual([second.entries.length, second.pending.length, second.pending[0]?.q], [0, 1, 3_000_000]);
  assert.equal(second.pending[0]?.authorization?.authority, me, "the signer is recovered once and kept with the queued read");
  // Both read: flagged with the original block, transaction and time.
  const third = await rescanPending(second.pending, deps(reading({ [me]: `0xef0100${dPoison.slice(2)}` })));
  assert.deepEqual(mergeEntries(third.entries).get(me), { k: "poisoner_delegation", c: "eip155:1", f: "poisoner-x", t: 0x7000, b: 0x30, x: "0xa1", d: dPoison });
  assert.deepEqual(third.pending, []);

  // A new delegate whose authorities cannot be read for its probe waits too, and is probed later.
  const dFwd = addr(0xd2);
  const fwdCode = `0x6080604052${"63aabbccdd15".repeat(20)}00`;
  const fwdBlock: RawBlock = { number: "0x31", timestamp: "0x7010", transactions: [{ hash: "0xa2", from: me, to: dFwd, nonce: "0x1", type: "0x4", authorizationList: [await auth(dFwd)] }] };
  const unprobed = await scanBlocks([fwdBlock], { ...deps(async (reqs) => reqs.map((r) => (r.params[0] === dFwd ? fwdCode : undefined))), simulate: forwarding });
  assert.equal(delegates.get(dFwd)?.class, "unprobed");
  assert.equal(unprobed.pending.length, 1);
  const probed = await rescanPending(unprobed.pending, { ...deps(reading({ [me]: `0xef0100${dFwd.slice(2)}` })), simulate: forwarding });
  assert.equal(delegates.get(dFwd)?.class, "forwarder");
  assert.deepEqual(mergeEntries(probed.entries).get(me), { k: "forwarding_delegation", c: "eip155:1", f: delegates.get(dFwd)?.family, t: 0x7010, b: 0x31, x: "0xa2", d: dFwd });
});

// --- cron: the queue, the anchor, the KV budget ---------------------------------------

/** An in-memory KV that counts operations as Workers KV does: a bulk read of up to 100 keys is one. */
function memoryKv(): KVNamespace & { data: Map<string, string>; puts: string[]; reads: number } {
  const data = new Map<string, string>();
  const puts: string[] = [];
  const kv = {
    data,
    puts,
    reads: 0,
    get: (async (key: string | string[]) => {
      kv.reads++;
      if (!Array.isArray(key)) return data.get(key) ?? null;
      assert.ok(key.length <= 100, "a bulk read takes at most 100 keys");
      return new Map(key.map((k) => [k, data.get(k) ?? null]));
    }) as KVNamespace["get"],
    put: async (key: string, value: string) => {
      puts.push(key);
      data.set(key, value);
    },
  };
  return kv;
}

/** One JSON-RPC stub for every endpoint of both chains; `code` answers eth_getCode (undefined: rate-limited). */
function chainStub(opts: { head?: number; blocks?: Record<number, RawBlock["transactions"]>; code?: (address: string) => string | undefined; log?: string[]; missing?: (block: number) => boolean }): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req | Req[];
    const answer = (r: Req) => {
      opts.log?.push(r.method === "eth_getCode" ? `code ${String(r.params[0])}` : r.method);
      if (r.method === "eth_blockNumber") return { jsonrpc: "2.0", id: r.id, result: `0x${(opts.head ?? 0x200).toString(16)}` };
      if (r.method === "eth_getBlockByNumber") {
        const n = Number.parseInt(r.params[0] as string, 16);
        if (opts.missing?.(n)) return { jsonrpc: "2.0", id: r.id, result: null };
        return { jsonrpc: "2.0", id: r.id, result: { number: r.params[0], timestamp: "0x6400", transactions: opts.blocks?.[n] ?? [] } };
      }
      if (r.method === "eth_getCode") {
        const code = opts.code?.(String(r.params[0]).toLowerCase());
        return code === undefined ? { jsonrpc: "2.0", id: r.id, error: { code: -32005, message: "rate limited" } } : { jsonrpc: "2.0", id: r.id, result: code };
      }
      return { jsonrpc: "2.0", id: r.id, result: null };
    };
    return new Response(JSON.stringify(Array.isArray(req) ? req.map(answer) : answer(req)));
  }) as unknown as typeof fetch;
}

function seeded(): ReturnType<typeof memoryKv> {
  const kv = memoryKv();
  kv.data.set(KW.registry, JSON.stringify({ updated_at: "2026-10-02", families: [KIT] }));
  kv.data.set(KW.cursor("eip155:1"), "99");
  kv.data.set(KW.cursor("eip155:8453"), "499");
  return kv;
}
const kitCreation = { 100: [{ hash: "0xc1", from: DEPLOYER, to: null, nonce: "0x0" }] };

test("cron: a read that still fails is queued (one KV write), signed as pending, and re-read first on the next run", async () => {
  const kv = seeded();
  const down = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ blocks: kitCreation, code: (a) => (a === KIT_ADDRESS ? undefined : "0x") }), now: T })) as KitWatchStats;
  const eth = down.chains["eip155:1"] as ChainStats;
  assert.deepEqual([eth.cursor, eth.pending, eth.degraded], [114, 1, 1], "the cursor moves on; the read waits in the queue");
  assert.equal(kv.data.has(KW.address(KIT_ADDRESS)), false);
  assert.deepEqual(kv.puts.filter((k) => k.startsWith("kw:pending:")), [KW.pending("eip155:1")], "one write for the queue, none per address");
  // The coverage clock does not claim complete coverage while the read waits (it is pending, not a hole).
  assert.deepEqual(coverageOf(down), { complete_through: { "eip155:1": 114, "eip155:8453": 502 }, pending: { "eip155:1": 1 }, unbroken_since: { "eip155:1": 100, "eip155:8453": 500 } });

  const log: string[] = [];
  const up = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ blocks: kitCreation, code: (a) => (a === KIT_ADDRESS ? DRAINER : "0x"), log }), now: T + 60_000 })) as KitWatchStats;
  const entry = JSON.parse(kv.data.get(KW.address(KIT_ADDRESS)) as string) as WatchEntry;
  assert.deepEqual([entry.k, entry.b, entry.x, entry.t], ["drainer_kit_contract", 100, "0xc1", 0x6400], "evaluated with its original block");
  assert.deepEqual([up.chains["eip155:1"]?.pending, up.chains["eip155:1"]?.recovered], [0, 1]);
  assert.ok(log.indexOf(`code ${KIT_ADDRESS}`) >= 0 && log.indexOf(`code ${KIT_ADDRESS}`) < log.indexOf("eth_getBlockByNumber"), "queued reads come before new work");
  assert.equal(coverageOf(up).pending, undefined);
  assert.equal(kv.data.get(KW.pending("eip155:1")), "[]");
});

test("cron: the queue is bounded; a read a day old or pushed out is abandoned and counted as a hole; /status marks the chain degraded", async () => {
  const kv = seeded();
  const nowS = T / 1000;
  const queued = (i: number, q: number): PendingRead => ({ creation: { address: addr(0x10000 + i), deployer: addr(0x20000 + i), tx: `0x${i.toString(16)}`, block: 90 }, t: 0x6000, q });
  // 30 reads more than a day old, the rest of a full queue recent; the new blocks bring 50 more, none readable.
  kv.data.set(KW.pending("eip155:1"), JSON.stringify([...Array.from({ length: 30 }, (_, i) => queued(i, nowS - 90_000)), ...Array.from({ length: PENDING_MAX - 30 }, (_, i) => queued(100 + i, nowS - 600 + (i % 60)))]));
  const blocks = { 100: Array.from({ length: 50 }, (_, i) => ({ hash: `0xb${i}`, from: addr(0x30000 + i), to: null, nonce: "0x0" })) };
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ blocks, code: () => undefined }), now: T })) as KitWatchStats;
  const eth = st.chains["eip155:1"] as ChainStats;
  assert.deepEqual([eth.pending, eth.abandoned, eth.degraded], [PENDING_MAX, 50, 50], "30 expired and 20 pushed out of a full queue");
  assert.equal((JSON.parse(kv.data.get(KW.pending("eip155:1")) as string) as PendingRead[]).length, PENDING_MAX);
  assert.equal(kv.puts.filter((k) => k.startsWith("kw:pending:")).length, 1, "one queue write however many reads failed");
  const coverage = coverageOf(st);
  assert.deepEqual([coverage.gaps, coverage.pending], [{ "eip155:1": 50 }, { "eip155:1": PENDING_MAX }]);

  const view = kitWatchStatus({ ...st, updated_at: new Date(T).toISOString() }, T + 5_000) as { status: string; chains: Record<string, Record<string, unknown>> };
  assert.equal(view.status, "degraded");
  const e = (view.chains["eip155:1"] ?? {}) as Record<string, unknown>;
  assert.deepEqual([e.status, e.pending_reads, e.gaps, e.abandoned_reads, e.degraded_reads], ["degraded", PENDING_MAX, 50, 50, 50]);
  assert.deepEqual([view.chains["eip155:8453"]?.status, view.chains["eip155:8453"]?.pending_reads], ["ok", 0]);
  assert.equal(JSON.stringify(view).includes(addr(0x10000 + 100).slice(2)), false, "aggregates only: no address in /status");
});

test("cron: every skipped range is counted, past the last 10 the stats keep", async () => {
  const kv = seeded();
  const ranges = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, to: i * 10 + 5, at: "" }));
  const eth: ChainStats = { cursor: 1000, head: 1000, last_run: "", scanned_blocks: 1, flagged: {}, delegates: 0, gaps: ranges, gaps_total: 12, coverage_v: COVERAGE_V, unbroken_since: 900 };
  kv.data.set(KW.stats, JSON.stringify({ updated_at: "", chains: { "eip155:1": eth } }));
  kv.data.set(KW.cursor("eip155:8453"), String(0x10000 - 20));
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 0x10000 }), now: T })) as KitWatchStats;
  assert.deepEqual([st.chains["eip155:1"]?.gaps.length, st.chains["eip155:1"]?.gaps_total], [10, 13]);
  assert.deepEqual(coverageOf(st).gaps, { "eip155:1": 13 }, "the signed count is the real one, not the list's length");
  // Unbroken coverage restarts after the skipped range.
  assert.equal(st.chains["eip155:1"]?.unbroken_since, 0x10000 - 2 - 1800 + 1);
});

test("cron: watch-entry writes stay within a daily budget shared by both chains; when it is tight, the most severe kinds go first", async () => {
  const run = async (baseWritesToday: number, day = "2026-10-02") => {
    const kv = seeded();
    const base: ChainStats = { cursor: 499, head: 502, last_run: "", scanned_blocks: 0, flagged: {}, delegates: 0, gaps: [], day, writes_today: baseWritesToday };
    kv.data.set(KW.stats, JSON.stringify({ updated_at: "", chains: { "eip155:8453": base } }));
    const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ blocks: kitCreation, code: (a) => (a === KIT_ADDRESS ? DRAINER : "0x") }), now: T })) as KitWatchStats;
    return { kv, eth: st.chains["eip155:1"] as ChainStats };
  };
  // Room in the budget: the kit contract and its deployer are both written.
  const roomy = await run(0);
  assert.deepEqual([roomy.kv.data.has(KW.address(KIT_ADDRESS)), roomy.kv.data.has(KW.address(DEPLOYER)), roomy.eth.writes_today, roomy.eth.dropped_today], [true, true, 2, 0]);
  // The other chain has spent all but the reserve: only the most severe kind (the contract) is written.
  const tight = await run(DAILY_WRITE_BUDGET - 5_000);
  assert.deepEqual([tight.kv.data.has(KW.address(KIT_ADDRESS)), tight.kv.data.has(KW.address(DEPLOYER)), tight.eth.writes_today, tight.eth.dropped_today], [true, false, 1, 1]);
  // Spent: nothing more today. Yesterday's writes do not count.
  const spent = await run(DAILY_WRITE_BUDGET);
  assert.deepEqual([spent.kv.data.has(KW.address(KIT_ADDRESS)), spent.eth.writes_today, spent.eth.dropped_today], [false, 0, 2]);
  // An entry the caps leave out is a hole: counted, and unbroken coverage restarts after its block.
  assert.deepEqual([roomy.eth.gaps_total, roomy.eth.unbroken_since], [0, 100]);
  assert.deepEqual([tight.eth.gaps_total, tight.eth.unbroken_since], [1, 101]);
  assert.deepEqual([spent.eth.gaps_total, spent.eth.unbroken_since], [2, 101]);
  assert.equal((await run(DAILY_WRITE_BUDGET, "2026-10-01")).eth.writes_today, 2);
  // /status: the day's counts per chain; a new UTC day starts at zero.
  type View = { chains: Record<string, Record<string, unknown>> };
  const today = kitWatchStatus({ updated_at: new Date(T).toISOString(), chains: { "eip155:1": tight.eth } }, T + 1_000) as View;
  assert.deepEqual([today.chains["eip155:1"]?.writes_today, today.chains["eip155:1"]?.dropped_today, today.chains["eip155:1"]?.status], [1, 1, "ok"]);
  const tomorrow = kitWatchStatus({ updated_at: new Date(T + 86_400_000).toISOString(), chains: { "eip155:1": tight.eth } }, T + 86_400_000) as View;
  assert.deepEqual([tomorrow.chains["eip155:1"]?.writes_today, tomorrow.chains["eip155:1"]?.dropped_today], [0, 0]);
});

// --- provider 0.6.4: the lease, the block batch, honest coverage, the authorization key ---

test("cron lease: held for the whole run, so a concurrent run skips; released by the run's last write, after a throw too; a dead run's lease lapses", async () => {
  const kv = seeded();
  const stub = chainStub({});
  let open!: () => void;
  const gate = new Promise<void>((resolve) => (open = resolve));
  const gated = (async (url: string, init: RequestInit) => {
    await gate;
    return stub(url, init);
  }) as unknown as typeof fetch;
  const first = runKitWatch({ RATE: kv }, { fetchImpl: gated, now: T });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(kv.data.get(KW.lease), String(T), "the lease is taken before any RPC");
  // 90 s later the first run is still going (a cron placed far from its RPCs): the second one skips.
  assert.equal(await runKitWatch({ RATE: kv }, { fetchImpl: stub, now: T + 90_000 }), null);
  open();
  const done = (await first) as KitWatchStats;
  assert.equal(done.lease_released, T, "released by the stats it writes last");
  assert.ok(await runKitWatch({ RATE: kv }, { fetchImpl: stub, now: T + 95_000 }), "a finished run's lease is free at once");

  // A throw after the lease is taken still releases it.
  const broken = seeded();
  broken.data.set(KW.learned, "{}");
  await assert.rejects(runKitWatch({ RATE: broken }, { fetchImpl: stub, now: T }));
  assert.equal((JSON.parse(broken.data.get(KW.stats) as string) as KitWatchStats).lease_released, T);
  broken.data.set(KW.learned, "[]");
  assert.ok(await runKitWatch({ RATE: broken }, { fetchImpl: stub, now: T + 1_000 }));

  // A run that died holds its lease until it lapses.
  const dead = seeded();
  dead.data.set(KW.lease, String(T - 60_000));
  assert.equal(await runKitWatch({ RATE: dead }, { fetchImpl: stub, now: T }), null);
  assert.ok(await runKitWatch({ RATE: dead }, { fetchImpl: stub, now: T - 60_000 + LEASE_MS }));
});

test("cron: each chain's block batch carries over to its next run (no extra KV write)", async () => {
  const kv = seeded();
  const sizes: number[] = [];
  const stub = chainStub({});
  const logging = (async (url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req | Req[];
    if (Array.isArray(req) && req[0]?.method === "eth_getBlockByNumber") sizes.push(req.length);
    return stub(url, init);
  }) as unknown as typeof fetch;
  const first = (await runKitWatch({ RATE: kv }, { fetchImpl: logging, now: T })) as KitWatchStats;
  assert.equal(sizes[0], 2, "a first run starts small");
  assert.equal(first.chains["eip155:1"]?.block_batch, 10, "small blocks grow the batch to the endpoints' limit");
  const writes = kv.puts.length;
  sizes.length = 0;
  await runKitWatch({ RATE: kv }, { fetchImpl: logging, now: T + 60_000 });
  assert.equal(sizes[0], 10, "the next run starts where the last one left off");
  assert.equal(kv.puts.length - writes, writes, "the same writes per run as before");
});

test("coverage: stats from before 0.6.4 are migrated once: the reads dropped before 0.6.2 are holes, and unbroken coverage starts with the new code", async () => {
  const kv = seeded();
  const old: ChainStats = { cursor: 1000, head: 1002, last_run: "", scanned_blocks: 5000, flagged: {}, delegates: 0, gaps: [], gaps_total: 0, degraded: 9_884 };
  kv.data.set(KW.stats, JSON.stringify({ updated_at: "", chains: { "eip155:1": old } }));
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 1010 }), now: T })) as KitWatchStats;
  const eth = st.chains["eip155:1"] as ChainStats;
  assert.deepEqual([eth.gaps_total, eth.unbroken_since, eth.coverage_v], [LEGACY_DROPPED_READS["eip155:1"], 1001, COVERAGE_V]);
  // A chain with no earlier stats has no legacy holes; its coverage starts with its first block.
  assert.deepEqual([st.chains["eip155:8453"]?.gaps_total, st.chains["eip155:8453"]?.unbroken_since], [0, 500]);
  assert.deepEqual(coverageOf(st), { complete_through: { "eip155:1": 1008, "eip155:8453": 589 }, gaps: { "eip155:1": 9_884 }, unbroken_since: { "eip155:1": 1001, "eip155:8453": 500 } });
  // Once only.
  const again = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 1010 }), now: T + 60_000 })) as KitWatchStats;
  assert.deepEqual([again.chains["eip155:1"]?.gaps_total, again.chains["eip155:1"]?.unbroken_since], [9_884, 1001]);
  // /status states where unbroken coverage starts.
  const view = kitWatchStatus(again, Date.parse(again.updated_at)) as { chains: Record<string, Record<string, unknown>> };
  assert.equal(view.chains["eip155:1"]?.unbroken_since, 1001);
});

test("coverage: a queued read abandoned after a day is a hole, and unbroken coverage restarts after its block", async () => {
  const kv = seeded();
  const nowS = T / 1000;
  const eth: ChainStats = { cursor: 99, head: 101, last_run: "", scanned_blocks: 50, flagged: {}, delegates: 0, gaps: [], gaps_total: 0, unbroken_since: 50, coverage_v: COVERAGE_V };
  kv.data.set(KW.stats, JSON.stringify({ updated_at: "", chains: { "eip155:1": eth } }));
  const stale: PendingRead = { creation: { address: addr(0x31), deployer: addr(0x32), tx: "0x31", block: 95 }, t: 0x6000, q: nowS - 90_000 };
  kv.data.set(KW.pending("eip155:1"), JSON.stringify([stale]));
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({}), now: T })) as KitWatchStats;
  assert.deepEqual([st.chains["eip155:1"]?.gaps_total, st.chains["eip155:1"]?.abandoned, st.chains["eip155:1"]?.unbroken_since], [1, 1, 96]);
});

test("scan: past the per-scan bound authorizations are counted as holes; a settled delegate's are only counted, and never reach it", async () => {
  const delegate = addr(0x500);
  const tuples = (d: string, n: number, salt = 1): RawAuthorization[] => Array.from({ length: n }, (_, i) => ({ chainId: "0x1", address: d, nonce: `0x${i.toString(16)}`, yParity: "0x0", r: `0x${(i + salt).toString(16).padStart(64, "0")}`, s: `0x${"11".repeat(32)}` }));
  const blockWith = (list: RawAuthorization[]): RawBlock => ({ number: "0x40", timestamp: "0x7000", transactions: [{ hash: "0xf1", from: addr(0x501), to: addr(0x501), nonce: "0x0", type: "0x4", authorizationList: list }] });
  const act = addBlocks(newActivity(), [blockWith(tuples(delegate, MAX_AUTHORIZATIONS_PER_SCAN + 1))], "eip155:1");
  assert.deepEqual([act.authorizations.length, act.dropped, act.droppedBlock], [MAX_AUTHORIZATIONS_PER_SCAN, 1, 0x40]);
  const res = await scanActivity(act, { chain: "eip155:1", call: reading({ [delegate]: "0x" }), simulate: noSim, families: indexFamilies(null), delegates: new Map(), now: () => 1 });
  assert.deepEqual(res.holes, { count: 1, block: 0x40 });

  // A benign batch flood (a delegate judged not a threat, no re-probe due) and revocations: counted,
  // never kept, so they leave no hole and crowd out nothing.
  const benign = addr(0x502);
  const nowS = 10_000_000;
  const verdicts = (v: DelegateVerdict) => new Map<string, DelegateVerdict>([[benign, v]]);
  const flood = [...tuples(benign, 2 * MAX_AUTHORIZATIONS_PER_SCAN, 7), ...tuples("0x0000000000000000000000000000000000000000", 3, 9_000_000), ...tuples(delegate, 2, 9_500_000)];
  const quiet = addBlocks(newActivity(), [blockWith(flood)], "eip155:1", settledDelegates(verdicts({ class: "not_forwarding", at: nowS - 60, probes: 1 }), nowS));
  assert.deepEqual([quiet.authorizations.length, quiet.settled, quiet.dropped], [2, 2 * MAX_AUTHORIZATIONS_PER_SCAN + 3, 0]);
  // A re-probe due (6 h after the last, fewer than 3 probes): its authorizations are kept for it.
  assert.equal(settledDelegates(verdicts({ class: "not_forwarding", at: nowS - 7 * 3600, probes: 1 }), nowS)(benign), false);
  assert.equal(settledDelegates(verdicts({ class: "not_forwarding", at: nowS - 7 * 3600, probes: 3 }), nowS)(benign), true, "probed enough");
  assert.equal(settledDelegates(verdicts({ class: "unprobed", at: nowS }), nowS)(benign), false, "an unprobed delegate is never settled");
  assert.equal(settledDelegates(verdicts({ class: "forwarder", family: "fwd-x", at: nowS, bytes: 100, code_kind: "tiny" }), nowS)(benign), false, "a threat never is");
});

test("scan: a decoy reusing a real authorization's (r, s) for another delegate does not hide the real delegation (security review M2)", async () => {
  const dSweep = addr(0xd5);
  const dDecoy = addr(0xd6);
  const me = signer.address.toLowerCase();
  const families = indexFamilies({ updated_at: "", families: [fam("sweeper-z", "sweeper", kitCode(0x52, 97))] });
  const real = await auth(dSweep);
  const decoy: RawAuthorization = { ...real, address: dDecoy };
  const block: RawBlock = { number: "0x50", timestamp: "0x7100", transactions: [{ hash: "0xe1", from: addr(0x777), to: addr(0x777), nonce: "0x0", type: "0x4", authorizationList: [decoy, real] }] };
  const call = reading({ [dSweep]: kitCode(0x5a, 5), [dDecoy]: "0x", [me]: `0xef0100${dSweep.slice(2)}` });
  const res = await scanBlocks([block], { chain: "eip155:1", call, simulate: noSim, families, delegates: new Map(), now: () => 1 });
  assert.deepEqual(mergeEntries(res.entries).get(me), { k: "sweeper_delegation", c: "eip155:1", f: "sweeper-z", t: 0x7100, b: 0x50, x: "0xe1", d: dSweep }, "the victim is flagged");
  // The same tuple repeated is still one authorization.
  const replay: RawBlock = { ...block, transactions: [{ hash: "0xe2", from: addr(0x777), to: addr(0x777), nonce: "0x1", type: "0x4", authorizationList: [real, { ...real, nonce: "0x00", yParity: "0x00" }] }] };
  assert.equal(addBlocks(newActivity(), [replay], "eip155:1").authorizations.length, 1);
});

test("scan: a delegate that could not be probed (budget spent, simulation down) leaves its authorizations queued with their first queue time", async () => {
  const dFwd = addr(0xd7);
  const me = signer.address.toLowerCase();
  const fwdCode = `0x6080604052${"63aabbccdd17".repeat(20)}00`;
  const block: RawBlock = { number: "0x60", timestamp: "0x7200", transactions: [{ hash: "0xe3", from: me, to: dFwd, nonce: "0x2", type: "0x4", authorizationList: [await auth(dFwd)] }] };
  const delegates = new Map<string, DelegateVerdict>();
  const deps = (simulate: SimulateCall, maxProbes: number, now: number): ScanDeps => ({ chain: "eip155:1", call: reading({ [dFwd]: fwdCode, [me]: `0xef0100${dFwd.slice(2)}` }), simulate, families: indexFamilies(null), delegates, maxProbes, now: () => now });
  const noBudget = await scanBlocks([block], deps(forwarding, 0, 4_000_000));
  assert.equal(delegates.get(dFwd)?.class, "unprobed");
  assert.deepEqual([noBudget.pending.length, noBudget.stats.deferred], [1, 1], "not dropped: it waits for a probe");
  const down = await rescanPending(noBudget.pending, deps(noSim, 6, 4_000_060));
  assert.deepEqual([down.pending.length, down.pending[0]?.q, down.entries.length], [1, 4_000_000, 0], "simulation down: still waiting, with its first queue time");
  const up = await rescanPending(down.pending, deps(forwarding, 6, 4_000_120));
  assert.deepEqual([up.pending.length, mergeEntries(up.entries).get(me)?.k], [0, "forwarding_delegation"]);
});

test("scan: past the run's evaluation budget, a threat's authorizations wait for a later run instead of being dropped", async () => {
  const dPoison = addr(0xd8);
  const me = signer.address.toLowerCase();
  const families = indexFamilies({ updated_at: "", families: [fam("poisoner-y", "poisoner", kitCode(0x53, 96))] });
  const list = await Promise.all(Array.from({ length: 101 }, async (_, nonce) => {
    const a = await signer.signAuthorization({ address: dPoison as `0x${string}`, chainId: 1, nonce });
    return { chainId: "0x1", address: dPoison, nonce: `0x${nonce.toString(16)}`, yParity: `0x${(a.yParity ?? 0).toString(16)}`, r: a.r, s: a.s } as RawAuthorization;
  }));
  const block: RawBlock = { number: "0x70", timestamp: "0x7300", transactions: [{ hash: "0xe4", from: me, to: me, nonce: "0x3", type: "0x4", authorizationList: list }] };
  const budget = { evaluations: 100 };
  const deps: ScanDeps = { chain: "eip155:1", call: reading({ [dPoison]: kitCode(0x5b, 6), [me]: `0xef0100${dPoison.slice(2)}` }), simulate: noSim, families, delegates: new Map(), now: () => 5_000_000, budget };
  const first = await scanBlocks([block], deps);
  assert.equal(mergeEntries(first.entries).get(me)?.k, "poisoner_delegation");
  assert.deepEqual([first.pending.length, first.stats.deferred, budget.evaluations], [1, 1, 0], "the 101st waits, it is not dropped");
  // The budget is the run's: another scan in the same run evaluates nothing more.
  const sameRun = await rescanPending(first.pending, deps);
  assert.deepEqual([sameRun.pending.length, sameRun.entries.length, sameRun.pending[0]?.q], [1, 0, first.pending[0]?.q]);
  // The next run has a budget of its own.
  const later = await rescanPending(sameRun.pending, { ...deps, budget: { evaluations: 100 } });
  assert.deepEqual([later.pending.length, mergeEntries(later.entries).get(me)?.k], [0, "poisoner_delegation"]);
});

test("cron: a flood of delegations to a threat is worked off at the chain's budget, the rest queued, with no hole and bounded KV operations", async () => {
  const kv = memoryKv();
  kv.data.set(KW.registry, JSON.stringify({ updated_at: "2026-10-15", families: [KIT, fam("poisoner-q", "poisoner", POISONER)] }));
  kv.data.set(KW.cursor("eip155:1"), "99");
  kv.data.set(KW.cursor("eip155:8453"), "499");
  const dPoison = addr(0xd0d);
  // 700 look-alikes, each delegating to the poisoner in one batch transaction.
  const keys = Array.from({ length: 700 }, (_, i) => privateKeyToAccount(`0x${(i + 1).toString(16).padStart(64, "0")}`));
  const list = await Promise.all(keys.map(async (k) => {
    const a = await k.signAuthorization({ address: dPoison as `0x${string}`, chainId: 1, nonce: 0 });
    return { chainId: "0x1", address: dPoison, nonce: "0x0", yParity: `0x${(a.yParity ?? 0).toString(16)}`, r: a.r, s: a.s } as RawAuthorization;
  }));
  const authorities = new Set(keys.map((k) => k.address.toLowerCase()));
  // 100 of them were flagged before: they need no write, and do not count against the cap.
  for (const k of keys.slice(0, 100)) kv.data.set(KW.address(k.address.toLowerCase()), JSON.stringify({ k: "poisoner_delegation", c: "eip155:1", f: "poisoner-q", t: 1, d: dPoison }));
  const stub = chainStub({ blocks: { 100: [{ hash: "0xf00d", from: addr(0x9), to: addr(0x9), nonce: "0x0", type: "0x4", authorizationList: list }] }, code: (a) => (a === dPoison ? POISONER : authorities.has(a) ? `0xef0100${dPoison.slice(2)}` : "0x") });
  const flaggedNow = () => keys.filter((k) => kv.data.has(KW.address(k.address.toLowerCase()))).length;

  const first = (await runKitWatch({ RATE: kv }, { fetchImpl: stub, now: T })) as KitWatchStats;
  const eth = first.chains["eip155:1"] as ChainStats;
  // Ethereum's budget is 400 evaluations: 100 already flagged + 300 new; 300 wait in the queue.
  assert.deepEqual([flaggedNow(), eth.writes_today, eth.pending, eth.gaps_total ?? 0], [400, 300, 300, 0]);
  assert.ok(kv.reads + kv.puts.length < 600, `KV operations in the run: ${kv.reads + kv.puts.length}`);

  const second = (await runKitWatch({ RATE: kv }, { fetchImpl: stub, now: T + 60_000 })) as KitWatchStats;
  const eth2 = second.chains["eip155:1"] as ChainStats;
  assert.deepEqual([flaggedNow(), eth2.writes_today, eth2.pending, eth2.gaps_total ?? 0, eth2.flagged.poisoner_delegation], [700, 600, 0, 0, 600]);
  assert.equal(coverageOf(second).gaps, undefined, "no hole: the flood was worked off, not dropped");
});

test("cron: a queued read the run could not evaluate is not counted as recovered", async () => {
  const kv = seeded();
  const nowS = T / 1000;
  const dFwd = addr(0xd9);
  const me = signer.address.toLowerCase();
  kv.data.set(KW.delegates("eip155:1"), JSON.stringify({ [dFwd]: { class: "unprobed", at: nowS - 100, bytes: 120, code_kind: "tiny" } }));
  const queued: PendingRead = { authorization: { delegate: dFwd, tx: "0xe5", block: 95, raw: await auth(dFwd) }, t: 0x6000, q: nowS - 100 };
  kv.data.set(KW.pending("eip155:1"), JSON.stringify([queued]));
  // The chain stub answers no simulation: the delegate cannot be probed this run.
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ code: (a) => (a === me ? `0xef0100${dFwd.slice(2)}` : "0x") }), now: T })) as KitWatchStats;
  assert.deepEqual([st.chains["eip155:1"]?.recovered, st.chains["eip155:1"]?.pending], [0, 1]);
});

test("cron: the queue is retried by cost: at most 100 reads a run, a threat's authorizations within the budget, and settled delegates' at no cost", async () => {
  const kv = seeded();
  const nowS = T / 1000;
  const dSettled = addr(0xa51);
  const dThreat = addr(0xa52);
  const me = signer.address.toLowerCase();
  kv.data.set(KW.delegates("eip155:1"), JSON.stringify({ [dSettled]: { class: "not_forwarding", at: nowS - 60, probes: 3 }, [dThreat]: { class: "poisoner", family: "poisoner-r", at: nowS - 60 } }));
  const creation = (i: number): PendingRead => ({ creation: { address: addr(0x40000 + i), deployer: addr(0x50000 + i), tx: `0x${i.toString(16)}`, block: 95 }, t: 0x6000, q: nowS - 300 });
  const authorization = async (delegate: string, nonce: number): Promise<PendingRead> => {
    const a = await signer.signAuthorization({ address: delegate as `0x${string}`, chainId: 1, nonce });
    return { authorization: { delegate, tx: `0xa${nonce}`, block: 96, raw: { chainId: "0x1", address: delegate, nonce: `0x${nonce.toString(16)}`, yParity: `0x${(a.yParity ?? 0).toString(16)}`, r: a.r, s: a.s } }, t: 0x6000, q: nowS - 200 };
  };
  const queue = [...Array.from({ length: 150 }, (_, i) => creation(i)), ...(await Promise.all(Array.from({ length: 10 }, (_, i) => authorization(dSettled, i)))), ...(await Promise.all(Array.from({ length: 5 }, (_, i) => authorization(dThreat, 20 + i))))];
  kv.data.set(KW.pending("eip155:1"), JSON.stringify(queue));
  const log: string[] = [];
  // The creations' code still cannot be read (an outage); the poisoner's look-alike is delegated to it.
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ code: (a) => (a === me ? `0xef0100${dThreat.slice(2)}` : a.startsWith("0x00000000000000000000000000000000000") ? undefined : "0x"), log }), now: T })) as KitWatchStats;
  // Distinct addresses: the RPC layer asks each endpoint in turn for what the last one left unanswered.
  const creationReads = new Set(log.filter((l) => l.startsWith("code 0x000000000000000000000000000000000004"))).size;
  assert.equal(creationReads, 100, "100 queued reads retried, not 150");
  assert.equal(JSON.parse(kv.data.get(KW.address(me)) as string).k, "poisoner_delegation", "the threat's authorizations were evaluated");
  assert.deepEqual([st.chains["eip155:1"]?.pending, st.chains["eip155:1"]?.recovered, st.chains["eip155:1"]?.abandoned ?? 0], [150, 15, 0], "the settled delegate's 10 cost nothing; the 150 reads wait");
});

test("cron: a segment whose blocks no endpoint serves ends the run's scan there: earlier segments are kept, the next run resumes, nothing is skipped", async () => {
  const kv = seeded();
  // Base: cursor 499, head 600 − 10 confirmations; blocks from 530 on cannot be fetched this run.
  const stuck = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 600, missing: (n) => n >= 530 && n < 1000 }), now: T })) as KitWatchStats;
  const base = stuck.chains["eip155:8453"] as ChainStats;
  assert.deepEqual([base.cursor, base.gaps_total ?? 0], [529, 0], "three segments kept, no hole");
  // Every endpoint was asked; the two that serve evaluations last.
  assert.match(base.error ?? "", /^Error: blocks 530-530 unavailable \((?:[a-z0-9.-]+: incomplete; ){5}mainnet\.base\.org: incomplete; base-rpc\.publicnode\.com: incomplete\)$/);
  assert.equal(stuck.chains["eip155:1"]?.error, undefined, "the other chain is untouched");
  assert.equal(coverageOf(stuck).complete_through["eip155:8453"], 529);
  const view = kitWatchStatus(stuck, Date.parse(stuck.updated_at)) as { chains: Record<string, Record<string, unknown>> };
  assert.equal(view.chains["eip155:8453"]?.status, "error");

  const resumed = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 600 }), now: T + 60_000 })) as KitWatchStats;
  const base2 = resumed.chains["eip155:8453"] as ChainStats;
  assert.deepEqual([base2.cursor, base2.error, base2.gaps_total ?? 0, base2.scanned_blocks], [590, undefined, 0, 91], "resumed at 530: every block from 500 to 590 scanned once");
});

test("blocks: an endpoint that answers 429 is not asked again in the run; when all are limited the fetch fails at once", async () => {
  const asked: string[] = [];
  const limiting = new Set(["blastapi"]);
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req[];
    asked.push(host(url));
    if ([...limiting].some((name) => url.includes(name))) return new Response("slow down", { status: 429 });
    return new Response(JSON.stringify(req.map((r) => ({ jsonrpc: "2.0", id: r.id, result: { number: r.params[0], timestamp: "0x1", transactions: [] } }))));
  }) as unknown as typeof fetch;
  const rpc = kitWatchRpc("eip155:1", { fetchImpl, blockBatch: 1, scanEndpoints: ETH_SCAN });
  await rpc.eachBlocks(100, 103, () => undefined);
  // Block 100 alone, then 101-103 in one batch (small blocks grow it): BlastAPI is asked once.
  assert.deepEqual(asked, ["eth-mainnet.public.blastapi.io", "mainnet.gateway.tenderly.co", "mainnet.gateway.tenderly.co"]);
  asked.length = 0;
  limiting.add("tenderly").add("publicnode");
  const batch = rpc.blockBatchSize();
  await assert.rejects(rpc.eachBlocks(104, 110, () => undefined), /^Error: blocks 104-110 unavailable \(eth-mainnet\.public\.blastapi\.io: HTTP 429 earlier in this run; mainnet\.gateway\.tenderly\.co: HTTP 429; ethereum-rpc\.publicnode\.com: HTTP 429\)$/);
  assert.deepEqual(asked, ["mainnet.gateway.tenderly.co", "ethereum-rpc.publicnode.com"], "nothing more for BlastAPI, and no smaller retries");
  assert.equal(rpc.blockBatchSize(), batch, "a rate limit does not shrink the batch");
});

test("scan endpoints: those that serve paid evaluations come last, after every one that does not", async () => {
  const { SCAN_ENDPOINTS, RPC_ENDPOINTS, SIMULATION_ENDPOINTS } = await import("../src/rpc.js");
  for (const [chain, list] of Object.entries(SCAN_ENDPOINTS)) {
    const evaluation = new Set([...(RPC_ENDPOINTS[chain] ?? []), ...(SIMULATION_ENDPOINTS[chain] ?? [])]);
    const firstEvaluation = list.findIndex((u) => evaluation.has(u));
    assert.ok(firstEvaluation > 0, `${chain}: at least one endpoint that serves no evaluation, first`);
    assert.ok(list.slice(firstEvaluation).every((u) => evaluation.has(u)), `${chain}: nothing after the evaluation endpoints`);
    assert.equal(new Set(list).size, list.length, `${chain}: no duplicates`);
  }
});

test("a delegate that had no code is classified again: its verdict expires after a day, and a family deployed at its address replaces it", async () => {
  const kv = seeded();
  const nowS = T / 1000;
  const dEmpty = addr(0xe0e);
  const dOld = addr(0xe0f);
  // KIT_ADDRESS is DEPLOYER's CREATE at nonce 0 (kitCreation, block 100): judged "not a threat" while it had no code.
  kv.data.set(KW.delegates("eip155:1"), JSON.stringify({
    [dEmpty]: { class: "not_forwarding", at: nowS - 90_000, code_kind: "none", probes: 3 },
    [dOld]: { class: "not_forwarding", at: nowS - 90_000, code_kind: "logic", bytes: 400, probes: 3 },
    [KIT_ADDRESS]: { class: "not_forwarding", at: nowS - 60, code_kind: "none", probes: 3 },
  }));
  kv.data.set(KW.registry, JSON.stringify({ updated_at: "2026-10-16", families: [KIT, fam("sweeper-k", "sweeper", DRAINER)] }));
  await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ blocks: kitCreation, code: (a) => (a === KIT_ADDRESS ? DRAINER : "0x") }), now: T });
  const after = JSON.parse(kv.data.get(KW.delegates("eip155:1")) as string) as Record<string, DelegateVerdict>;
  assert.equal(after[dEmpty], undefined, "a day-old no-code verdict expires: the delegate is read again when seen");
  assert.equal(after[dOld]?.class, "not_forwarding", "a delegate with code keeps its verdict for 30 days");
  assert.deepEqual([after[KIT_ADDRESS]?.class, after[KIT_ADDRESS]?.family], ["sweeper", "sweeper-k"], "a sweeper deployed at the address replaces the old verdict");
});

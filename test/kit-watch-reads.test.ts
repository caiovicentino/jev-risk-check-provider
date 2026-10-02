// Kit watch reads (provider 0.6.2). A read one endpoint leaves unanswered goes to the next one;
// a read that still fails is queued and evaluated on a later run with its original block; the
// signed coverage clock states the reads still queued and every hole; KV writes per run and per
// day stay bounded, and blocks are fetched in batches sized by their JSON.
import { test } from "node:test";
import assert from "node:assert";
import { privateKeyToAccount } from "viem/accounts";
import { codeFacts } from "../src/code-fingerprint.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import { indexFamilies, mergeEntries, rescanPending, scanBlocks, type DelegateVerdict, type Family, type PendingRead, type RawAuthorization, type RawBlock, type ScanDeps, type SimulateCall, type WatchEntry } from "../src/kit-watch.js";
import { coverageOf, DAILY_WRITE_BUDGET, kitWatchStatus, KW, PENDING_MAX, runKitWatch, type ChainStats, type KitWatchStats } from "../deploy/kit-watch.js";
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
  const rpc = kitWatchRpc("eip155:1", { fetchImpl });
  const got: number[] = [];
  await rpc.eachBlocks(100, 109, (blocks) => {
    events.push(`hand ${blocks.length}`);
    got.push(...blocks.map((b) => Number.parseInt(b.number, 16)));
  });
  assert.deepEqual(got, Array.from({ length: 10 }, (_, i) => 100 + i), "every block, in order");
  // 2 blocks of ~800 KB fill the 2 MB a request asks for. The incomplete batch is fetched whole from
  // the next endpoint, and the scan's order is kept for the next batch (evaluation endpoints last).
  assert.deepEqual(events, ["fetch 2", "fetch 2 mainnet.gateway.tenderly.co", "hand 2", "fetch 2", "hand 2", "fetch 2", "hand 2", "fetch 2", "hand 2", "fetch 2", "hand 2"]);
  // Small blocks grow the batch up to the endpoints' limit of 10.
  pad = "";
  events.length = 0;
  assert.equal((await rpc.blocks(200, 219)).length, 20);
  assert.deepEqual(events, ["fetch 2", "fetch 10", "fetch 8"]);
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

function memoryKv(): KVNamespace & { data: Map<string, string>; puts: string[] } {
  const data = new Map<string, string>();
  const puts: string[] = [];
  return {
    data,
    puts,
    get: (async (key: string) => data.get(key) ?? null) as KVNamespace["get"],
    put: async (key: string, value: string) => {
      puts.push(key);
      data.set(key, value);
    },
  };
}

/** One JSON-RPC stub for every endpoint of both chains; `code` answers eth_getCode (undefined: rate-limited). */
function chainStub(opts: { head?: number; blocks?: Record<number, RawBlock["transactions"]>; code?: (address: string) => string | undefined; log?: string[] }): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as Req | Req[];
    const answer = (r: Req) => {
      opts.log?.push(r.method === "eth_getCode" ? `code ${String(r.params[0])}` : r.method);
      if (r.method === "eth_blockNumber") return { jsonrpc: "2.0", id: r.id, result: `0x${(opts.head ?? 0x200).toString(16)}` };
      if (r.method === "eth_getBlockByNumber") return { jsonrpc: "2.0", id: r.id, result: { number: r.params[0], timestamp: "0x6400", transactions: opts.blocks?.[Number.parseInt(r.params[0] as string, 16)] ?? [] } };
      if (r.method === "eth_getCode") {
        const code = opts.code?.(String(r.params[0]).toLowerCase());
        return code === undefined ? { jsonrpc: "2.0", id: r.id, error: { code: -32005, message: "rate limited" } } : { jsonrpc: "2.0", id: r.id, result: code };
      }
      return { jsonrpc: "2.0", id: r.id, result: null };
    };
    return new Response(JSON.stringify(Array.isArray(req) ? req.map(answer) : answer(req)));
  }) as unknown as typeof fetch;
}

function seeded(): KVNamespace & { data: Map<string, string>; puts: string[] } {
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
  // The coverage clock does not claim unbroken coverage while the read waits.
  assert.deepEqual(coverageOf(down), { complete_through: { "eip155:1": 114, "eip155:8453": 502 }, pending: { "eip155:1": 1 } });

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
  // 30 reads more than a day old, 470 recent; the new blocks bring 50 more, none readable.
  kv.data.set(KW.pending("eip155:1"), JSON.stringify([...Array.from({ length: 30 }, (_, i) => queued(i, nowS - 90_000)), ...Array.from({ length: 470 }, (_, i) => queued(100 + i, nowS - 600 + (i % 60)))]));
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
  const eth: ChainStats = { cursor: 1000, head: 1000, last_run: "", scanned_blocks: 1, flagged: {}, delegates: 0, gaps: ranges, gaps_total: 12 };
  kv.data.set(KW.stats, JSON.stringify({ updated_at: "", chains: { "eip155:1": eth } }));
  kv.data.set(KW.cursor("eip155:8453"), String(0x10000 - 20));
  const st = (await runKitWatch({ RATE: kv }, { fetchImpl: chainStub({ head: 0x10000 }), now: T })) as KitWatchStats;
  assert.deepEqual([st.chains["eip155:1"]?.gaps.length, st.chains["eip155:1"]?.gaps_total], [10, 13]);
  assert.deepEqual(coverageOf(st).gaps, { "eip155:1": 13 }, "the signed count is the real one, not the list's length");
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
  assert.equal((await run(DAILY_WRITE_BUDGET, "2026-10-01")).eth.writes_today, 2);
  // /status: the day's counts per chain; a new UTC day starts at zero.
  type View = { chains: Record<string, Record<string, unknown>> };
  const today = kitWatchStatus({ updated_at: new Date(T).toISOString(), chains: { "eip155:1": tight.eth } }, T + 1_000) as View;
  assert.deepEqual([today.chains["eip155:1"]?.writes_today, today.chains["eip155:1"]?.dropped_today, today.chains["eip155:1"]?.status], [1, 1, "ok"]);
  const tomorrow = kitWatchStatus({ updated_at: new Date(T + 86_400_000).toISOString(), chains: { "eip155:1": tight.eth } }, T + 86_400_000) as View;
  assert.deepEqual([tomorrow.chains["eip155:1"]?.writes_today, tomorrow.chains["eip155:1"]?.dropped_today], [0, 0]);
});

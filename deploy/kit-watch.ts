import { EOA_KINDS, indexFamilies, KIND_RANK, scanBlocks, WATCH_CHAINS, type DelegateVerdict, type Family, type FamilyIndex, type KitWatchCoverage, type KitWatchLookup, type Registry, type ScanResult, type WatchChain, type WatchEntry } from "../src/kit-watch.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import type { WorkerEnv } from "./runtime.js";

// Kit watch in production. A cron (every minute) scans the new blocks of Ethereum and
// Base with src/kit-watch.ts and keeps what it finds in KV; evaluations read it. All of
// it is private: the registry is seeded by scripts/kit-registry.ts --upload (partly
// GPL-derived), the rest is the provider's own observation.

export const KW = {
  registry: "kw:registry",
  learned: "kw:learned",
  stats: "kw:stats",
  lease: "kw:lease",
  delegates: (chain: WatchChain) => `kw:delegates:${chain}`,
  cursor: (chain: WatchChain) => `kw:cursor:${chain}`,
  address: (address: string) => `kw:a:${address}`,
};
export const WATCH_TTL_S = 365 * 86400;
const DELEGATE_BENIGN_TTL_S = 30 * 86400;
/**
 * Watch entries written per chain per run. A Worker invocation may make at most 1,000 KV
 * operations; each entry costs a read and a write, so both chains together stay far below it,
 * whatever a crafted transaction flags. The most important kinds are written first.
 */
const MAX_WRITES_PER_CHAIN = 200;

type ChainPlan = { confirmations: number; perRun: number; start: number; maxLag: number };
const PLAN: Record<WatchChain, ChainPlan> = {
  // ~5 blocks a minute; a run catches up to 15.
  "eip155:1": { confirmations: 2, perRun: 15, start: 5, maxLag: 1800 },
  // ~30 blocks a minute; a run catches up to 90, in segments of 10 (memory).
  "eip155:8453": { confirmations: 10, perRun: 90, start: 30, maxLag: 10800 },
};
const SEGMENT = 10;

export type ChainStats = {
  cursor: number;
  head: number;
  last_run: string;
  scanned_blocks: number;
  flagged: Partial<Record<WatchEntry["k"], number>>;
  delegates: number;
  gaps: Array<{ from: number; to: number; at: string }>;
  /** Code reads that failed (retried later) and entries not written this run (over the per-run cap). */
  degraded?: number;
  dropped?: number;
  error?: string;
};
export type KitWatchStats = { updated_at: string; chains: Partial<Record<WatchChain, ChainStats>> };

async function readJson<T>(env: WorkerEnv, key: string, fallback: T): Promise<T> {
  const raw = env.RATE ? await env.RATE.get(key) : null;
  return raw ? (JSON.parse(raw) as T) : fallback;
}

/** One chain: cursor → scan → watchlist, delegates, learned families. */
async function scanChain(env: WorkerEnv, chain: WatchChain, families: FamilyIndex, stats: KitWatchStats, fetchImpl?: typeof fetch): Promise<Family[]> {
  const kv = env.RATE;
  if (!kv) return [];
  const plan = PLAN[chain];
  const rpc = kitWatchRpc(chain, { timeoutMs: 15000, ...(fetchImpl ? { fetchImpl } : {}) });
  const prev: ChainStats = stats.chains[chain] ?? { cursor: 0, head: 0, last_run: "", scanned_blocks: 0, flagged: {}, delegates: 0, gaps: [] };
  const head = (await rpc.head()) - plan.confirmations;
  // The cursor lives in the stats (one write per run); kw:cursor:<chain> only seeds it (backfill upload).
  const stored = prev.cursor > 0 ? prev.cursor : Number((await kv.get(KW.cursor(chain))) ?? Number.NaN);
  let from = Number.isFinite(stored) ? stored + 1 : head - plan.start + 1;
  // Too far behind (an outage): skip ahead and record the gap; coverage is reported, not implied.
  if (head - from > plan.maxLag) {
    prev.gaps = [...prev.gaps, { from, to: head - plan.maxLag, at: new Date().toISOString() }].slice(-10);
    from = head - plan.maxLag + 1;
  }
  const to = Math.min(head, from + plan.perRun - 1);
  const delegates = new Map(Object.entries(await readJson<Record<string, DelegateVerdict>>(env, KW.delegates(chain), {})));
  const delegatesBefore = JSON.stringify([...delegates]);
  const learned: Family[] = [];
  const entries: ScanResult["entries"] = [];
  let scanned = 0;
  let degraded = 0;
  for (let n = from; n <= to; n += SEGMENT) {
    const blocks = await rpc.blocks(n, Math.min(to, n + SEGMENT - 1));
    const res = await scanBlocks(blocks, { chain, call: rpc.call, simulate: rpc.simulate, families, delegates, maxProbes: 6 });
    entries.push(...res.entries);
    learned.push(...res.learned);
    scanned += blocks.length;
    degraded += res.stats.degraded;
  }
  // First sighting wins; a stronger kind replaces a weaker one.
  const merged = new Map<string, WatchEntry>();
  for (const { address, entry } of entries) {
    const m = merged.get(address);
    if (!m || KIND_RANK[entry.k] > KIND_RANK[m.k]) merged.set(address, entry);
  }
  const ordered = [...merged].sort(([, a], [, b]) => KIND_RANK[b.k] - KIND_RANK[a.k]);
  const dropped = Math.max(0, ordered.length - MAX_WRITES_PER_CHAIN);
  for (const [address, entry] of ordered.slice(0, MAX_WRITES_PER_CHAIN)) {
    const existing = await kv.get(KW.address(address));
    const old = existing ? (JSON.parse(existing) as WatchEntry) : null;
    if (old && KIND_RANK[old.k] >= KIND_RANK[entry.k]) continue;
    await kv.put(KW.address(address), JSON.stringify(old ? { ...entry, t: Math.min(old.t, entry.t) } : entry), { expirationTtl: WATCH_TTL_S });
    prev.flagged[entry.k] = (prev.flagged[entry.k] ?? 0) + 1;
  }
  // Benign verdicts expire (a delegate seen again is simply re-probed); malicious ones never do.
  const cutoff = Math.floor(Date.now() / 1000) - DELEGATE_BENIGN_TTL_S;
  for (const [d, v] of delegates) if ((v.class === "not_forwarding" || v.class === "unprobed") && v.at < cutoff) delegates.delete(d);
  if (JSON.stringify([...delegates]) !== delegatesBefore) await kv.put(KW.delegates(chain), JSON.stringify(Object.fromEntries(delegates)));
  stats.chains[chain] = {
    ...prev,
    cursor: Math.max(to, prev.cursor, from - 1),
    head,
    last_run: new Date().toISOString(),
    scanned_blocks: prev.scanned_blocks + scanned,
    delegates: delegates.size,
    degraded: (prev.degraded ?? 0) + degraded,
    dropped: (prev.dropped ?? 0) + dropped,
  };
  if (degraded || dropped) console.warn(`kit watch ${chain}: ${degraded} code reads failed, ${dropped} entries over the per-run cap`);
  delete stats.chains[chain]?.error;
  return learned;
}

/** The cron: both chains, bounded work per run; a lease keeps overlapping runs apart. */
export async function runKitWatch(env: WorkerEnv, opts: { fetchImpl?: typeof fetch; now?: number } = {}): Promise<KitWatchStats | null> {
  const kv = env.RATE;
  if (!kv || env.KIT_WATCH === "off") return null;
  const now = opts.now ?? Date.now();
  const lease = Number((await kv.get(KW.lease)) ?? 0);
  if (now - lease < 30_000) return null;
  await kv.put(KW.lease, String(now), { expirationTtl: 120 });
  const registry = await readJson<Registry>(env, KW.registry, { updated_at: "", families: [] });
  const learned = await readJson<Family[]>(env, KW.learned, []);
  const families = indexFamilies({ updated_at: registry.updated_at, families: [...registry.families, ...learned] });
  const stats = await readJson<KitWatchStats>(env, KW.stats, { updated_at: "", chains: {} });
  const newlyLearned: Family[] = [];
  try {
    for (const chain of WATCH_CHAINS) {
      try {
        newlyLearned.push(...(await scanChain(env, chain, families, stats, opts.fetchImpl)));
      } catch (err) {
        console.error(`kit watch ${chain} failed: ${String(err).slice(0, 200)}`);
        const prev = stats.chains[chain];
        if (prev) prev.error = String(err).slice(0, 200);
        else stats.chains[chain] = { cursor: 0, head: 0, last_run: new Date(now).toISOString(), scanned_blocks: 0, flagged: {}, delegates: 0, gaps: [], error: String(err).slice(0, 200) };
      }
    }
    const fresh = newlyLearned.filter((f, i) => !learned.some((l) => l.id === f.id) && newlyLearned.findIndex((x) => x.id === f.id) === i);
    if (fresh.length) await kv.put(KW.learned, JSON.stringify([...learned, ...fresh]));
  } finally {
    // The run is always recorded, so /status can tell a stalled watch from a quiet one.
    stats.updated_at = new Date().toISOString();
    await kv.put(KW.stats, JSON.stringify(stats));
  }
  return stats;
}

const FAMILY_TTL_MS = 5 * 60 * 1000;
let familyCache: { at: number; value: Promise<{ index: FamilyIndex; asOf: string; coverage: KitWatchCoverage }> } | null = null;
const delegateCache = new Map<WatchChain, { at: number; value: Promise<Record<string, DelegateVerdict>> }>();

/** The coverage clock from the cron's stats: the cursor is the last block a run completed. */
export function coverageOf(stats: KitWatchStats): KitWatchCoverage {
  const complete_through: Record<string, number> = {};
  const gaps: Record<string, number> = {};
  for (const chain of WATCH_CHAINS) {
    const c = stats.chains[chain];
    if (!c || !(c.cursor > 0)) continue;
    complete_through[chain] = c.cursor;
    if (c.gaps?.length) gaps[chain] = c.gaps.length;
  }
  return { complete_through, ...(Object.keys(gaps).length ? { gaps } : {}) };
}

async function loadFamilies(env: WorkerEnv): Promise<{ index: FamilyIndex; asOf: string; coverage: KitWatchCoverage }> {
  const [registry, learned, stats] = await Promise.all([
    readJson<Registry>(env, KW.registry, { updated_at: "", families: [] }),
    readJson<Family[]>(env, KW.learned, []),
    readJson<KitWatchStats>(env, KW.stats, { updated_at: "", chains: {} }),
  ]);
  if (!registry.families.length) throw new Error("kit watch registry not seeded");
  return { index: indexFamilies({ updated_at: registry.updated_at, families: [...registry.families, ...learned] }), asOf: stats.updated_at || registry.updated_at, coverage: coverageOf(stats) };
}

/** Evaluation-time lookups: watchlist entries per address (KV), families (cached 5 min). */
export function kitWatchLookup(env: WorkerEnv): KitWatchLookup | null {
  const kv = env.RATE;
  if (!kv || env.KIT_WATCH === "off") return null;
  const families = () => {
    if (!familyCache || Date.now() - familyCache.at > FAMILY_TTL_MS) familyCache = { at: Date.now(), value: loadFamilies(env) };
    const value = familyCache.value;
    value.catch(() => (familyCache = null));
    return value;
  };
  const delegates = (chain: WatchChain) => {
    const hit = delegateCache.get(chain);
    if (hit && Date.now() - hit.at < FAMILY_TTL_MS) return hit.value;
    const value = readJson<Record<string, DelegateVerdict>>(env, KW.delegates(chain), {});
    value.catch(() => delegateCache.delete(chain));
    delegateCache.set(chain, { at: Date.now(), value });
    return value;
  };
  return {
    families: async () => (await families()).index,
    asOf: async () => (await families()).asOf,
    coverage: async () => (await families()).coverage,
    delegate: async (network, delegate) => ((WATCH_CHAINS as readonly string[]).includes(network) ? (await delegates(network as WatchChain))[delegate] : undefined),
    addresses: async (addresses, network) => {
      const out = new Map<string, WatchEntry>();
      const unique = [...new Set(addresses.map((a) => a.toLowerCase()))].slice(0, 16);
      const raws = await Promise.all(unique.map((a) => kv.get(KW.address(a), { type: "text", cacheTtl: 60 })));
      unique.forEach((a, i) => {
        const raw = raws[i];
        if (!raw) return;
        const entry = JSON.parse(raw) as WatchEntry;
        // Who controls an EOA holds on every chain; a contract is only itself where it was seen.
        if (EOA_KINDS.has(entry.k) || entry.c === network) out.set(a, entry);
      });
      return out;
    },
  };
}

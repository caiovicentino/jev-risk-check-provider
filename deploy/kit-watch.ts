import { addBlocks, EOA_KINDS, indexFamilies, KIND_RANK, newActivity, rescanPending, scanActivity, WATCH_CHAINS, type DelegateVerdict, type Family, type FamilyIndex, type KitWatchCoverage, type KitWatchLookup, type PendingRead, type Registry, type ScanDeps, type ScanResult, type WatchChain, type WatchEntry } from "../src/kit-watch.js";
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
  pending: (chain: WatchChain) => `kw:pending:${chain}`,
  address: (address: string) => `kw:a:${address}`,
};
export const WATCH_TTL_S = 365 * 86400;
const DELEGATE_BENIGN_TTL_S = 30 * 86400;
/**
 * Watch entries handled per chain per run. A Worker invocation may make at most 1,000 KV
 * operations; each entry costs a read and a write, so both chains together stay far below it,
 * whatever a crafted transaction flags. The most important kinds are written first.
 */
const MAX_WRITES_PER_CHAIN = 200;
/**
 * Watch-entry writes per UTC day, both chains together. Workers Paid includes 1M KV writes a
 * month and the cron's own bookkeeping takes up to ~260k of them; a busy day writes a few thousand
 * entries. The last part of the budget is kept for the most severe kinds (kit contracts and
 * delegations to labelled poisoners and sweepers), and each run writes the most severe first.
 */
export const DAILY_WRITE_BUDGET = 25_000;
const RESERVED_WRITES = 5_000;
const RESERVED_MIN_RANK = KIND_RANK.drainer_kit_contract;
/**
 * Reads still failing after the RPC's retries wait in one KV value per chain (written at most once
 * a run, never once per address) and are re-read before new work. A read a day old, or pushed out
 * of a full queue, is abandoned and counted as a hole in the coverage.
 */
export const PENDING_MAX = 500;
const PENDING_TTL_S = 86400;
/** Queued reads retried per chain per run; those that still fail go to the back. */
const PENDING_RETRY_PER_RUN = 100;
/** /status marks a chain degraded at this many queued reads. */
export const PENDING_DEGRADED = 50;
/** The cron runs every minute: stats older than 3 minutes mean the watch has stalled. */
const KIT_WATCH_STALE_S = 180;

type ChainPlan = { confirmations: number; perRun: number; start: number; maxLag: number };
const PLAN: Record<WatchChain, ChainPlan> = {
  // ~5 blocks a minute; a run catches up to 15.
  "eip155:1": { confirmations: 2, perRun: 15, start: 5, maxLag: 1800 },
  // ~30 blocks a minute; a run catches up to 90, in segments of 10.
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
  /** The last 10 ranges skipped after outages. */
  gaps: Array<{ from: number; to: number; at: string }>;
  /** Every hole ever recorded: each range skipped (the list above keeps the last 10) and each read abandoned. */
  gaps_total?: number;
  /** Code reads that failed after the RPC's retries, each queued for a later run. */
  degraded?: number;
  /** Reads queued now, recovered from the queue, and abandoned (a day old, or the queue full). */
  pending?: number;
  recovered?: number;
  abandoned?: number;
  /** Entries not written: over the per-run cap or the daily write budget. */
  dropped?: number;
  /** The UTC day `writes_today` and `dropped_today` count. */
  day?: string;
  writes_today?: number;
  dropped_today?: number;
  error?: string;
};
export type KitWatchStats = { updated_at: string; chains: Partial<Record<WatchChain, ChainStats>> };

/** Every hole in a chain's coverage (stats from before 0.6.2 have only the list). */
export function gapCount(c: Pick<ChainStats, "gaps" | "gaps_total">): number {
  return Math.max(c.gaps_total ?? 0, c.gaps?.length ?? 0);
}

async function readJson<T>(env: WorkerEnv, key: string, fallback: T): Promise<T> {
  const raw = env.RATE ? await env.RATE.get(key) : null;
  return raw ? (JSON.parse(raw) as T) : fallback;
}

const pendingKey = (p: PendingRead) => (p.creation ? `c:${p.creation.address}` : `a:${p.authorization?.raw.r}|${p.authorization?.raw.s}`);

/** One chain: queued reads, then cursor → scan → watchlist, delegates, learned families. */
async function scanChain(env: WorkerEnv, chain: WatchChain, families: FamilyIndex, stats: KitWatchStats, opts: { fetchImpl?: typeof fetch | undefined; now: number }): Promise<Family[]> {
  const kv = env.RATE;
  if (!kv) return [];
  const plan = PLAN[chain];
  const rpc = kitWatchRpc(chain, { timeoutMs: 15000, ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}) });
  const nowS = Math.floor(opts.now / 1000);
  const today = new Date(opts.now).toISOString().slice(0, 10);
  const prev: ChainStats = stats.chains[chain] ?? { cursor: 0, head: 0, last_run: "", scanned_blocks: 0, flagged: {}, delegates: 0, gaps: [] };
  const head = (await rpc.head()) - plan.confirmations;
  // The cursor lives in the stats (one write per run); kw:cursor:<chain> only seeds it (backfill upload).
  const stored = prev.cursor > 0 ? prev.cursor : Number((await kv.get(KW.cursor(chain))) ?? Number.NaN);
  let from = Number.isFinite(stored) ? stored + 1 : head - plan.start + 1;
  let gaps = prev.gaps;
  let holes = gapCount(prev);
  // Too far behind (an outage): skip ahead and record the gap; coverage is reported, not implied.
  if (head - from > plan.maxLag) {
    gaps = [...gaps, { from, to: head - plan.maxLag, at: new Date(opts.now).toISOString() }].slice(-10);
    holes++;
    from = head - plan.maxLag + 1;
  }
  const to = Math.min(head, from + plan.perRun - 1);
  const delegates = new Map(Object.entries(await readJson<Record<string, DelegateVerdict>>(env, KW.delegates(chain), {})));
  const delegatesBefore = JSON.stringify([...delegates]);
  const deps: ScanDeps = { chain, call: rpc.call, simulate: rpc.simulate, families, delegates, maxProbes: 6, now: () => nowS };
  const learned: Family[] = [];
  const entries: ScanResult["entries"] = [];

  // Reads that failed on earlier runs come first: a day-old one is abandoned, the rest are retried.
  const queueBefore = (await kv.get(KW.pending(chain))) ?? "[]";
  const queued = JSON.parse(queueBefore) as PendingRead[];
  let queue = queued.filter((p) => nowS - p.q <= PENDING_TTL_S);
  let abandoned = queued.length - queue.length;
  let recovered = 0;
  if (queue.length) {
    const retry = queue.slice(0, PENDING_RETRY_PER_RUN);
    const res = await rescanPending(retry, deps);
    entries.push(...res.entries);
    learned.push(...res.learned);
    recovered = retry.length - res.pending.length;
    queue = [...queue.slice(retry.length), ...res.pending];
  }

  let scanned = 0;
  let degraded = 0;
  for (let n = from; n <= to; n += SEGMENT) {
    const act = newActivity();
    // Each batch's block bodies are dropped once its activity is taken: full blocks are large.
    await rpc.eachBlocks(n, Math.min(to, n + SEGMENT - 1), (blocks) => void addBlocks(act, blocks, chain));
    const res = await scanActivity(act, deps);
    entries.push(...res.entries);
    learned.push(...res.learned);
    scanned += act.blocks;
    degraded += res.stats.degraded;
    queue.push(...res.pending);
  }
  // One entry per read; a full queue gives way at its oldest reads.
  const seen = new Set<string>();
  queue = queue.filter((p) => {
    const key = pendingKey(p);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (queue.length > PENDING_MAX) {
    const oldest = new Set([...queue].sort((a, b) => a.q - b.q).slice(0, queue.length - PENDING_MAX));
    abandoned += oldest.size;
    queue = queue.filter((p) => !oldest.has(p));
  }

  // First sighting wins; a stronger kind replaces a weaker one.
  const merged = new Map<string, WatchEntry>();
  for (const { address, entry } of entries) {
    const m = merged.get(address);
    if (!m || KIND_RANK[entry.k] > KIND_RANK[m.k]) merged.set(address, entry);
  }
  const ordered = [...merged].sort(([, a], [, b]) => KIND_RANK[b.k] - KIND_RANK[a.k]);
  // The daily budget is shared: what the other chain wrote today counts too.
  const otherWrites = WATCH_CHAINS.reduce((n, c) => n + (c !== chain && stats.chains[c]?.day === today ? (stats.chains[c]?.writes_today ?? 0) : 0), 0);
  let writes = prev.day === today ? (prev.writes_today ?? 0) : 0;
  let handled = 0;
  let dropped = 0;
  for (const [address, entry] of ordered) {
    const left = DAILY_WRITE_BUDGET - otherWrites - writes;
    if (handled >= MAX_WRITES_PER_CHAIN || left <= 0 || (left <= RESERVED_WRITES && KIND_RANK[entry.k] < RESERVED_MIN_RANK)) {
      dropped++;
      continue;
    }
    handled++;
    const existing = await kv.get(KW.address(address));
    const old = existing ? (JSON.parse(existing) as WatchEntry) : null;
    if (old && KIND_RANK[old.k] >= KIND_RANK[entry.k]) continue;
    await kv.put(KW.address(address), JSON.stringify(old ? { ...entry, t: Math.min(old.t, entry.t) } : entry), { expirationTtl: WATCH_TTL_S });
    writes++;
    prev.flagged[entry.k] = (prev.flagged[entry.k] ?? 0) + 1;
  }
  // Benign verdicts expire (a delegate seen again is simply re-probed); malicious ones never do.
  const cutoff = nowS - DELEGATE_BENIGN_TTL_S;
  for (const [d, v] of delegates) if ((v.class === "not_forwarding" || v.class === "unprobed") && v.at < cutoff) delegates.delete(d);
  if (JSON.stringify([...delegates]) !== delegatesBefore) await kv.put(KW.delegates(chain), JSON.stringify(Object.fromEntries(delegates)));
  const queueAfter = JSON.stringify(queue);
  if (queueAfter !== queueBefore) await kv.put(KW.pending(chain), queueAfter);
  stats.chains[chain] = {
    ...prev,
    cursor: Math.max(to, prev.cursor, from - 1),
    head,
    last_run: new Date().toISOString(),
    scanned_blocks: prev.scanned_blocks + scanned,
    delegates: delegates.size,
    gaps,
    gaps_total: holes + abandoned,
    degraded: (prev.degraded ?? 0) + degraded,
    pending: queue.length,
    recovered: (prev.recovered ?? 0) + recovered,
    abandoned: (prev.abandoned ?? 0) + abandoned,
    dropped: (prev.dropped ?? 0) + dropped,
    day: today,
    writes_today: writes,
    dropped_today: (prev.day === today ? (prev.dropped_today ?? 0) : 0) + dropped,
  };
  if (degraded || abandoned || dropped) console.warn(`kit watch ${chain}: ${degraded} code reads queued, ${queue.length} pending, ${abandoned} abandoned, ${dropped} entries not written (caps)`);
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
        newlyLearned.push(...(await scanChain(env, chain, families, stats, { fetchImpl: opts.fetchImpl, now })));
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

/**
 * The coverage clock from the cron's stats: the cursor is the last block a run read; every hole
 * ever recorded and every read still queued is stated next to it, so it never implies unbroken
 * coverage that the watch does not have.
 */
export function coverageOf(stats: KitWatchStats): KitWatchCoverage {
  const complete_through: Record<string, number> = {};
  const gaps: Record<string, number> = {};
  const pending: Record<string, number> = {};
  for (const chain of WATCH_CHAINS) {
    const c = stats.chains[chain];
    if (!c || !(c.cursor > 0)) continue;
    complete_through[chain] = c.cursor;
    const holes = gapCount(c);
    if (holes) gaps[chain] = holes;
    if (c.pending) pending[chain] = c.pending;
  }
  return { complete_through, ...(Object.keys(gaps).length ? { gaps } : {}), ...(Object.keys(pending).length ? { pending } : {}) };
}

/** The watch in /status: coverage and counts per chain, never an address. */
export function kitWatchStatus(st: KitWatchStats, nowMs: number): Record<string, unknown> {
  // Stats older than the cron's cadence allows mean the watch has stalled, whatever lag they last recorded.
  const age = Math.max(0, Math.round((nowMs - Date.parse(st.updated_at)) / 1000));
  const stale = !Number.isFinite(age) || age > KIT_WATCH_STALE_S;
  const today = new Date(nowMs).toISOString().slice(0, 10);
  const chains: Record<string, Record<string, unknown> & { status: string }> = {};
  for (const [chain, c] of Object.entries(st.chains)) {
    if (!c) continue;
    const pending = c.pending ?? 0;
    const sameDay = c.day === today;
    chains[chain] = {
      // Many reads waiting means the scan is not seeing everything it reads past.
      status: c.error ? "error" : pending >= PENDING_DEGRADED ? "degraded" : "ok",
      lag_blocks: Math.max(0, c.head - c.cursor),
      scanned_blocks: c.scanned_blocks,
      flagged: c.flagged,
      delegates_classified: c.delegates,
      gaps: gapCount(c),
      pending_reads: pending,
      ...(c.degraded ? { degraded_reads: c.degraded } : {}),
      ...(c.recovered ? { recovered_reads: c.recovered } : {}),
      ...(c.abandoned ? { abandoned_reads: c.abandoned } : {}),
      writes_today: sameDay ? (c.writes_today ?? 0) : 0,
      dropped_today: sameDay ? (c.dropped_today ?? 0) : 0,
      ...(c.dropped ? { dropped_entries: c.dropped } : {}),
      ...(c.error ? { error: c.error } : {}),
    };
  }
  return {
    status: stale ? "stale" : Object.values(chains).some((c) => c.status !== "ok") ? "degraded" : "ok",
    updated_at: st.updated_at,
    age_s: Number.isFinite(age) ? age : null,
    chains,
    note: "EIP-7702 delegations to poisoners and sweepers, and new drainer-kit deployments, observed block by block; the list itself is private",
  };
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

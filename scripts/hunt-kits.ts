// Kit watch backfill: scans a block range of Ethereum or Base with the same code the
// Worker cron runs (src/kit-watch.ts), and writes what it finds to .cache/intel/.
//
//   npx tsx scripts/hunt-kits.ts --chain eip155:1 --hours 24 [--concurrency 4] [--upload]
//   npx tsx scripts/hunt-kits.ts --chain eip155:8453 --from 51900000 --to 51910000
//   npx tsx scripts/hunt-kits.ts --chain eip155:1 --retry      # segments an earlier run could not fetch
//   npx tsx scripts/hunt-kits.ts --chain eip155:1 --upload-all # no scan: store everything found so far in KV,
//                                                               # and start the Worker cron where the backfill ended
//
// Outputs (private: provider intelligence, partly derived from GPL data):
//   .cache/intel/watch-eip155-<id>.json      address → WatchEntry (merged with earlier runs)
//   .cache/intel/delegates-eip155-<id>.json  delegate → verdict
//   .cache/intel/learned-families.json   behaviour-learned families
// --upload writes new watch entries and the delegate verdicts to the Worker KV.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { indexFamilies, mergeEntries, scanBlocks, KIND_RANK, WATCH_CHAINS, type DelegateVerdict, type Family, type Registry, type ScanResult, type WatchChain, type WatchEntry } from "../src/kit-watch.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import { codeFacts, isContractCode } from "../src/code-fingerprint.js";

const INTEL = new URL("../.cache/intel/", import.meta.url);
/** File-name form of a CAIP-2 id ("eip155:1" → "eip155-1"): a colon would read as a URL scheme. */
export const slug = (chain: string): string => chain.replace(":", "-");
const BLOCK_SECONDS: Record<WatchChain, number> = { "eip155:1": 12, "eip155:8453": 2 };
export const WATCH_TTL_S = 365 * 86400;

const arg = (name: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
};

function readJson<T>(name: string, fallback: T): T {
  const file = new URL(name, INTEL);
  return existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as T) : fallback;
}

export type HuntResult = { chain: WatchChain; from: number; to: number; stats: ScanResult["stats"]; entries: Map<string, WatchEntry>; learned: Family[]; seconds: number; failedSegments: number[] };

export async function hunt(chain: WatchChain, from: number, to: number, opts: { concurrency?: number; segment?: number; starts?: number[]; registry: Registry; delegates: Map<string, DelegateVerdict>; onProgress?: (done: number, total: number) => void }): Promise<HuntResult> {
  const started = Date.now();
  const rpc = kitWatchRpc(chain, { timeoutMs: 45000 });
  const families = indexFamilies(opts.registry);
  const segment = opts.segment ?? 50;
  const starts: number[] = opts.starts ? [...opts.starts] : [];
  if (!opts.starts) for (let n = from; n <= to; n += segment) starts.push(n);
  const stats: ScanResult["stats"] = { blocks: 0, creations: 0, authorizations: 0, delegates_new: 0, probes: 0, kit_contracts: 0, flagged_authorities: 0 };
  const all: ScanResult["entries"] = [];
  const learned: Family[] = [];
  const failedSegments: number[] = [];
  let next = 0;
  let done = 0;
  await Promise.all(
    Array.from({ length: opts.concurrency ?? 4 }, async () => {
      while (next < starts.length) {
        const start = starts[next++] as number;
        const end = opts.starts ? start + segment - 1 : Math.min(to, start + segment - 1);
        let ok = false;
        for (let attempt = 0; attempt < 4 && !ok; attempt++) {
          try {
            const blocks = await rpc.blocks(start, end);
            const res = await scanBlocks(blocks, { chain, call: rpc.call, simulate: rpc.simulate, families, delegates: opts.delegates, maxProbes: 50 });
            for (const k of Object.keys(stats) as Array<keyof typeof stats>) stats[k] += res.stats[k];
            all.push(...res.entries);
            learned.push(...res.learned);
            ok = true;
          } catch {
            await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)));
          }
        }
        if (!ok) failedSegments.push(start);
        opts.onProgress?.(++done, starts.length);
      }
    }),
  );
  return { chain, from, to, stats, entries: mergeEntries(all), learned, seconds: Math.round((Date.now() - started) / 1000), failedSegments };
}

function kvBulkPut(pairs: Array<{ key: string; value: string; expiration_ttl?: number }>): void {
  for (let i = 0; i < pairs.length; i += 10000) {
    const file = new URL(`kv-bulk-${i}.json`, INTEL);
    writeFileSync(file, JSON.stringify(pairs.slice(i, i + 10000)));
    execFileSync("npx", ["wrangler", "kv", "bulk", "put", fileURLToPath(file), "--binding", "RATE", "--remote", "--config", "deploy/wrangler.toml"], { stdio: "inherit" });
  }
}

async function main(): Promise<void> {
  const chain = (arg("chain") ?? "eip155:1") as WatchChain;
  if (!WATCH_CHAINS.includes(chain)) throw new Error(`--chain must be one of ${WATCH_CHAINS.join(", ")}`);
  mkdirSync(INTEL, { recursive: true });
  const registry = readJson<Registry>("kit-registry.json", { updated_at: "", families: [] });
  if (!registry.families.length) throw new Error("run scripts/kit-registry.ts first");
  const learnedBefore = readJson<Family[]>("learned-families.json", []);
  registry.families.push(...learnedBefore);
  const delegates = new Map(Object.entries(readJson<Record<string, DelegateVerdict>>(`delegates-${slug(chain)}.json`, {})));
  if (process.argv.includes("--upload-all")) {
    const store = readJson<Record<string, WatchEntry>>(`watch-${slug(chain)}.json`, {});
    // Destinations must be plain wallets (src/kit-watch.ts); drop any contract an older scan recorded.
    const dests = Object.keys(store).filter((a) => store[a]?.k === "sweeper_destination");
    const destCodes = await kitWatchRpc(chain).call(dests.map((d) => ({ method: "eth_getCode", params: [d, "latest"] })));
    dests.forEach((d, i) => {
      const code = destCodes[i];
      if (typeof code !== "string" || isContractCode(codeFacts(code))) delete store[d];
    });
    writeFileSync(new URL(`watch-${slug(chain)}.json`, INTEL), JSON.stringify(store));
    const last = readJson<Record<string, number>>("backfill-cursors.json", {})[chain];
    kvBulkPut([
      ...Object.entries(store).map(([address, entry]) => ({ key: `kw:a:${address}`, value: JSON.stringify(entry), expiration_ttl: WATCH_TTL_S })),
      { key: `kw:delegates:${chain}`, value: JSON.stringify(Object.fromEntries(delegates)) },
      { key: "kw:learned", value: JSON.stringify(learnedBefore) },
      ...(last ? [{ key: `kw:cursor:${chain}`, value: String(last) }] : []),
    ]);
    return console.log(`${chain}: uploaded ${Object.keys(store).length} watch entries, ${delegates.size} delegate verdicts, ${learnedBefore.length} learned families${last ? `, cursor ${last}` : ""}`);
  }
  const rpc = kitWatchRpc(chain);
  const failedFile = `failed-${slug(chain)}.json`;
  const retry = process.argv.includes("--retry") ? readJson<number[]>(failedFile, []) : undefined;
  if (retry && !retry.length) return console.log(`${chain}: no failed segments to retry`);
  const head = (await rpc.head()) - (chain === "eip155:1" ? 2 : 10);
  const to = retry ? Math.max(...retry) + 49 : Number(arg("to") ?? head);
  const from = retry ? Math.min(...retry) : Number(arg("from") ?? to - Math.round((Number(arg("hours") ?? 1) * 3600) / BLOCK_SECONDS[chain]) + 1);
  console.log(`${chain}: ${retry ? `retrying ${retry.length} segments` : `blocks ${from}..${to} (${to - from + 1})`}, ${registry.families.length} families, ${delegates.size} known delegates`);
  let last = 0;
  const res = await hunt(chain, from, to, {
    ...(retry ? { starts: retry } : {}),
    concurrency: Number(arg("concurrency") ?? (retry ? 2 : 4)),
    registry,
    delegates,
    onProgress: (done, total) => {
      const pct = Math.floor((done / total) * 100);
      if (pct >= last + 10) {
        last = pct;
        console.log(`  ${pct}% (${done}/${total} segments)`);
      }
    },
  });

  // Merge with earlier runs: earliest sighting, strongest kind.
  const store = new Map(Object.entries(readJson<Record<string, WatchEntry>>(`watch-${slug(chain)}.json`, {})));
  const fresh: Array<[string, WatchEntry]> = [];
  for (const [address, entry] of res.entries) {
    const prev = store.get(address);
    if (!prev || KIND_RANK[entry.k] > KIND_RANK[prev.k] || (KIND_RANK[entry.k] === KIND_RANK[prev.k] && entry.t < prev.t)) {
      store.set(address, entry);
      fresh.push([address, entry]);
    }
  }
  writeFileSync(new URL(`watch-${slug(chain)}.json`, INTEL), JSON.stringify(Object.fromEntries(store)));
  writeFileSync(new URL(`delegates-${slug(chain)}.json`, INTEL), JSON.stringify(Object.fromEntries(delegates)));
  const learned = [...learnedBefore, ...res.learned.filter((f) => !learnedBefore.some((l) => l.id === f.id))];
  writeFileSync(new URL("learned-families.json", INTEL), JSON.stringify(learned));
  if (!retry) writeFileSync(new URL("backfill-cursors.json", INTEL), JSON.stringify({ ...readJson<Record<string, number>>("backfill-cursors.json", {}), [chain]: Math.max(to, readJson<Record<string, number>>("backfill-cursors.json", {})[chain] ?? 0) }));
  // Unfetched segments are kept for --retry: coverage is measured, never assumed.
  const stillFailed = retry ? res.failedSegments : [...new Set([...readJson<number[]>(failedFile, []), ...res.failedSegments])];
  writeFileSync(new URL(failedFile, INTEL), JSON.stringify(stillFailed.sort((a, b) => a - b)));

  const kinds = [...res.entries.values()].reduce<Record<string, number>>((m, e) => ((m[e.k] = (m[e.k] ?? 0) + 1), m), {});
  const families = [...res.entries.values()].reduce<Record<string, number>>((m, e) => ((m[e.f || "?"] = (m[e.f || "?"] ?? 0) + 1), m), {});
  const classes = [...delegates.values()].reduce<Record<string, number>>((m, v) => ((m[v.class] = (m[v.class] ?? 0) + 1), m), {});
  console.log(JSON.stringify({ chain, blocks: res.stats.blocks, seconds: res.seconds, failed_segments: res.failedSegments.length, stats: res.stats, addresses: res.entries.size, new_addresses: fresh.length, kinds, families, learned: res.learned.length, delegate_classes: classes }, null, 1));

  if (process.argv.includes("--upload")) {
    kvBulkPut(fresh.map(([address, entry]) => ({ key: `kw:a:${address}`, value: JSON.stringify(entry), expiration_ttl: WATCH_TTL_S })));
    kvBulkPut([
      { key: `kw:delegates:${chain}`, value: JSON.stringify(Object.fromEntries(delegates)) },
      { key: "kw:learned", value: JSON.stringify(learned) },
    ]);
    console.log(`uploaded ${fresh.length} watch entries and ${delegates.size} delegate verdicts`);
  }
}

if (process.argv[1]?.endsWith("hunt-kits.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

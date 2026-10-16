// How EIP-7702 authorizations on Ethereum split by what the kit watch knows about their delegate,
// and how bursty they are: the measurement behind v0.6.6 (authorizations to settled harmless
// delegates are counted, never kept; a threat's are evaluated within a per-run budget).
//
// It reads the most recent blocks from a public RPC (full transactions) in the cron's 10-block
// segments, and classifies each authorization by the watch's own delegate verdicts
// (KV `kw:delegates:eip155:1`, read with the operator's wrangler login, kept in memory only).
// The report carries aggregates only: no address, delegate or authority (the watchlist is private).
//
//   npx tsx eval/kit-watch-floods.ts [--blocks 3000] [--rpc https://ethereum-rpc.publicnode.com]
//
// Report: eval/evidence/kit-watch-floods-report.json. Costs nothing.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { EVAL_EVIDENCE_DIR } from "./harness.js";

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : String(process.argv[i + 1]);
};
const RPC = arg("rpc", "https://ethereum-rpc.publicnode.com");
const BLOCKS = Number(arg("blocks", "3000"));
const SEGMENT = 10;
const ZERO = "0x0000000000000000000000000000000000000000";

async function post(body: unknown): Promise<unknown> {
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30_000) });
      if (res.ok) return await res.json();
    } catch {
      // retried below
    }
    await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  throw new Error(`${RPC}: no answer`);
}

/** The watch's delegate verdicts, from KV through wrangler (never written to disk). */
function verdicts(): Map<string, string> {
  const ns = /binding\s*=\s*"RATE"\s*\n\s*id\s*=\s*"([0-9a-f]+)"/.exec(readFileSync("deploy/wrangler.toml", "utf8"))?.[1];
  if (!ns) throw new Error("no KV namespace in deploy/wrangler.toml");
  const out = execFileSync("npx", ["wrangler", "kv", "key", "get", "--namespace-id", ns, "kw:delegates:eip155:1", "--remote"], { cwd: "deploy", encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 });
  const json = JSON.parse(out.slice(out.indexOf("{"))) as Record<string, { class: string }>;
  return new Map(Object.entries(json).map(([d, v]) => [d.toLowerCase(), v.class]));
}

type Tx = { type?: string; authorizationList?: Array<{ address: string }> };

async function main(): Promise<void> {
  const known = verdicts();
  const head = Number.parseInt(((await post({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] })) as { result: string }).result, 16);
  const end = head - (head % SEGMENT) - 1;
  const start = end - BLOCKS + 1;
  const byClass = new Map<string, number>();
  const perDelegate = new Map<string, number>();
  const segments: number[] = [];
  let largestList = 0;
  let type4 = 0;
  let firstTime = 0;
  let lastTime = 0;
  for (let s = start; s <= end; s += SEGMENT) {
    const batch = Array.from({ length: SEGMENT }, (_, i) => ({ jsonrpc: "2.0", id: i + 1, method: "eth_getBlockByNumber", params: [`0x${(s + i).toString(16)}`, true] }));
    const blocks = (await post(batch)) as Array<{ result?: { timestamp: string; transactions: Tx[] } }>;
    let n = 0;
    for (const b of blocks) {
      if (!b.result) throw new Error(`a block of segment ${s} is missing`);
      const t = Number.parseInt(b.result.timestamp, 16);
      firstTime ||= t;
      lastTime = t;
      for (const tx of b.result.transactions) {
        if (tx.type !== "0x4") continue;
        type4++;
        const list = tx.authorizationList ?? [];
        largestList = Math.max(largestList, list.length);
        for (const a of list) {
          n++;
          const d = a.address.toLowerCase();
          const cls = d === ZERO ? "revocation" : (known.get(d) ?? "not_yet_classified");
          byClass.set(cls, (byClass.get(cls) ?? 0) + 1);
          perDelegate.set(d, (perDelegate.get(d) ?? 0) + 1);
        }
      }
    }
    segments.push(n);
  }
  const total = [...byClass.values()].reduce((x, y) => x + y, 0);
  const share = (k: number) => Math.round((k / Math.max(1, total)) * 1000) / 10;
  const top = [...perDelegate.values()].sort((a, b) => b - a);
  const sorted = [...segments].sort((a, b) => a - b);
  const settledClasses = ["not_forwarding", "revocation", "drainer_kit"];
  const report = {
    timestamp: new Date().toISOString(),
    chain: "eip155:1",
    rpc: new URL(RPC).hostname,
    blocks: { from: start, to: end, count: end - start + 1, from_time: new Date(firstTime * 1000).toISOString(), to_time: new Date(lastTime * 1000).toISOString() },
    method: "every EIP-7702 authorization in the blocks, classified by the kit watch's delegate verdicts at the time of the run; segments of 10 blocks, as the cron scans them; aggregates only",
    authorizations: total,
    type4_transactions: type4,
    by_verdict: Object.fromEntries([...byClass].sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, { count: v, pct: share(v) }])),
    settled_pct: share(settledClasses.reduce((x, c) => x + (byClass.get(c) ?? 0), 0)),
    threat_pct: share(["poisoner", "sweeper", "forwarder"].reduce((x, c) => x + (byClass.get(c) ?? 0), 0)),
    top_delegate_pct: share(top[0] ?? 0),
    top5_delegates_pct: share(top.slice(0, 5).reduce((x, y) => x + y, 0)),
    segments: { count: segments.length, median: sorted[Math.floor(sorted.length / 2)] ?? 0, max: sorted[sorted.length - 1] ?? 0, over_500: segments.filter((k) => k > 500).length, over_1000: segments.filter((k) => k > 1000).length, over_5000: segments.filter((k) => k > 5000).length },
    largest_list_in_one_transaction: largestList,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/kit-watch-floods-report.json`, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// Shadow evaluation of a facilitator's real traffic, from public on-chain data only.
//
// PayAI publishes its settlement signers (x402 v2 /supported → signers). Every payment it
// settles on Base is a transaction from one of them, and the transaction's Transfer logs
// are the payments (payer → payTo, amount). This replays x402check's deterministic checks
// on every payee and payer, as a pre-payment check would have seen them (no model calls):
// OFAC SDN (the same key across encodings), ScamSniffer's address list, the kit watch
// (watchlist, and the code each address runs now) and the code class (EOA, contract,
// EIP-7702 delegation).
//
//   npx tsx scripts/payai-shadow.ts [--days 7] [--facilitator https://facilitator.payai.network]
//   npx tsx scripts/payai-shadow.ts --reuse     # re-run the checks on the payments collected last time
//   npx tsx scripts/payai-shadow.ts --kv --out payai-shadow-2026-10-02-report.json
//
// --kv reads the kit watch as production has it now (registry, learned families and the
// watch entry of every payee and payer, from KV through wrangler) instead of the local
// backfill snapshot in .cache/intel. --out names the report (default payai-shadow-report.json).
//
// Outputs: eval/evidence/<out> (aggregates only: no addresses) and
// .cache/intel/payai-shadow-details.json (per-address results; private).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { codeFacts, isContractCode, resolveIndirection, type CodeFacts } from "../src/code-fingerprint.js";
import { indexFamilies, kindForCode, probeForwarding, runningFamily, EOA_KINDS, type Family, type Registry, type WatchEntry, type WatchKind } from "../src/kit-watch.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import { parseSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import { hashSetFromBytes } from "../src/threat-intel.js";
import { pool } from "./kit-catalog.js";

const BS = "https://base.blockscout.com/api/v2";
const NETWORK = "eip155:8453";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const INTEL = new URL("../.cache/intel/", import.meta.url);
const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : (process.argv[i + 1] as string);
};

async function getJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const res = await fetch(url, { ...init, headers: { accept: "application/json", "content-type": "application/json", "user-agent": "x402check-shadow/0.4" }, signal: AbortSignal.timeout(45000) });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
    }
  }
  return null;
}

type Tx = { hash: string; timestamp: string; status?: string; to?: { hash?: string } | null };

/** Every transaction a signer sent since `since` (Blockscout, newest first). A page that cannot be read aborts: coverage is never silently cut. */
async function signerTransactions(signer: string, since: number): Promise<Tx[]> {
  const out: Tx[] = [];
  let params = "filter=from";
  for (;;) {
    let page: { items?: Tx[]; next_page_params?: Record<string, unknown> | null } | null = null;
    for (let attempt = 0; attempt < 4 && !page; attempt++) {
      page = await getJson(`${BS}/addresses/${signer}/transactions?${params}`);
      if (!page) await new Promise((r) => setTimeout(r, 10_000));
    }
    if (!page) throw new Error(`${signer}: Blockscout page unreadable after ${out.length} transactions`);
    const items = page.items ?? [];
    for (const tx of items) if (Date.parse(tx.timestamp) >= since) out.push(tx);
    const oldest = items.length ? Date.parse((items[items.length - 1] as Tx).timestamp) : 0;
    if (!page.next_page_params || oldest < since) break;
    const next = Object.entries(page.next_page_params).filter(([k]) => k !== "filter");
    params = `filter=from&${new URLSearchParams(next.map(([k, v]): [string, string] => [k, String(v)])).toString()}`;
  }
  return out;
}

// Historical receipts: publicnode treats them as archive requests; these serve them.
const RECEIPT_RPC = ["https://base-mainnet.public.blastapi.io", "https://base.drpc.org"];

async function receipts(hashes: string[]): Promise<Array<{ logs?: Array<{ address: string; topics: string[]; data: string }> } | undefined>> {
  for (const [i, url] of RECEIPT_RPC.entries()) {
    const size = i === 0 ? hashes.length : 3; // drpc's free plan takes batches of 3
    const out: Array<{ logs?: Array<{ address: string; topics: string[]; data: string }> } | undefined> = [];
    let ok = true;
    for (let k = 0; k < hashes.length && ok; k += size) {
      const chunk = hashes.slice(k, k + size);
      const res = await getJson<Array<{ id: number; result?: { logs?: Array<{ address: string; topics: string[]; data: string }> } }>>(url, { method: "POST", body: JSON.stringify(chunk.map((h, j) => ({ jsonrpc: "2.0", id: j + 1, method: "eth_getTransactionReceipt", params: [h] }))) });
      if (!Array.isArray(res) || res.some((r) => !r.result)) ok = false;
      else out.push(...[...res].sort((a, b) => a.id - b.id).map((r) => r.result));
    }
    if (ok) return out;
  }
  return hashes.map(() => undefined);
}

type Payment = { tx: string; token: string; payer: string; payTo: string; amount: bigint; at: number };

async function payments(txs: Tx[]): Promise<{ payments: Payment[]; failed: number }> {
  const out: Payment[] = [];
  let failed = 0;
  const at = new Map(txs.map((t) => [t.hash, Date.parse(t.timestamp)]));
  const hashes = txs.filter((t) => t.status === "ok").map((t) => t.hash);
  const chunks: string[][] = [];
  for (let i = 0; i < hashes.length; i += 20) chunks.push(hashes.slice(i, i + 20));
  await pool(chunks, 3, async (chunk) => {
    const found = await receipts(chunk);
    chunk.forEach((hash, i) => {
      const r = found[i];
      if (!r) {
        failed++;
        return;
      }
      for (const l of r.logs ?? []) {
        if (l.topics[0] !== TRANSFER || l.topics.length !== 3 || l.data.length < 66) continue;
        const payer = `0x${(l.topics[1] as string).slice(26)}`;
        const payTo = `0x${(l.topics[2] as string).slice(26)}`;
        if (payer === payTo) continue;
        out.push({ tx: hash, token: l.address.toLowerCase(), payer, payTo, amount: BigInt(l.data.slice(0, 66)), at: at.get(hash) ?? 0 });
      }
    });
  });
  return { payments: out, failed };
}

type Verdict = { flags: string[]; code: CodeFacts["kind"] | "unknown"; delegateClass?: string };

/** Production KV through wrangler (deploy/wrangler.toml's RATE binding): one key, or many at once. */
function kvGet(key: string): string | null {
  try {
    return execFileSync("npx", ["wrangler", "kv", "key", "get", key, "--binding=RATE", "--remote"], { cwd: "deploy", encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
}
/** A binary KV value (a feed blob), or null. */
function kvGetBytes(key: string): Buffer | null {
  try {
    const b = execFileSync("npx", ["wrangler", "kv", "key", "get", key, "--binding=RATE", "--remote"], { cwd: "deploy", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 });
    return b.length % 8 === 0 && b.length > 0 ? b : null;
  } catch {
    return null;
  }
}
function kvBulkGet(keys: string[]): Map<string, string | null> {
  const out = new Map<string, string | null>();
  const file = new URL("kv-keys.json", INTEL);
  for (let i = 0; i < keys.length; i += 100) {
    writeFileSync(file, JSON.stringify(keys.slice(i, i + 100)));
    const raw = execFileSync("npx", ["wrangler", "kv", "bulk", "get", fileURLToPath(file), "--binding=RATE", "--remote"], { cwd: "deploy", encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 });
    const parsed = JSON.parse(raw.slice(raw.indexOf("{"))) as Record<string, string | null>;
    for (const [k, v] of Object.entries(parsed)) out.set(k, v);
  }
  return out;
}

async function main(): Promise<void> {
  const days = Number(arg("days", "7"));
  const facilitator = arg("facilitator", "https://facilitator.payai.network");
  const since = Date.now() - days * 86_400_000;
  const supported = await getJson<{ signers?: Record<string, string[]> }>(`${facilitator}/supported`);
  const signers = (supported?.signers?.["eip155:*"] ?? []).map((s) => s.toLowerCase());
  if (!signers.length) throw new Error("facilitator publishes no EVM signers");
  console.log(`${facilitator}: ${signers.length} EVM signers; window ${days} days`);

  const rpc = kitWatchRpc(NETWORK, { timeoutMs: 45000 });
  const cacheFile = new URL("payai-payments.json", INTEL);
  type Collected = { txs: number; active: number; failed: number; since: number; payments: Array<Omit<Payment, "amount"> & { amount: string }> };
  let collected: Collected;
  if (process.argv.includes("--reuse") && existsSync(cacheFile)) {
    collected = JSON.parse(readFileSync(cacheFile, "utf8")) as Collected;
  } else {
    const perSigner = await pool(signers, 3, async (s) => signerTransactions(s, since));
    const txs = perSigner.flat();
    const { payments: found, failed } = await payments(txs);
    collected = { txs: txs.length, active: perSigner.filter((l) => l.length > 0).length, failed, since, payments: found.map((p) => ({ ...p, amount: p.amount.toString() })) };
    mkdirSync(INTEL, { recursive: true });
    writeFileSync(cacheFile, JSON.stringify(collected));
  }
  const pays: Payment[] = collected.payments.map((p) => ({ ...p, amount: BigInt(p.amount) }));
  const { active, failed } = collected;
  const txs = { length: collected.txs };
  console.log(`  ${txs.length} settlement transactions from ${active} active signers; ${pays.length} payments (${failed} receipts unavailable)`);

  // --- deterministic checks on every payee and payer ---
  const feeds = loadFeedsFromDisk();
  if (process.argv.includes("--kv")) {
    // ScamSniffer's address set as production uses it now (GPL: runtime data, never written to the repo).
    const blob = kvGetBytes("feed:scamsniffer:addresses:v1");
    const meta = kvGet("feed:scamsniffer:meta:v1");
    if (!blob || !meta) throw new Error("--kv: the production ScamSniffer address set could not be read");
    feeds.scamsnifferAddresses = { set: hashSetFromBytes(blob), as_of: (JSON.parse(meta) as { as_of: string }).as_of };
  }
  const fromKv = process.argv.includes("--kv");
  const kvRegistry = fromKv ? kvGet("kw:registry") : null;
  const kvLearned = fromKv ? kvGet("kw:learned") : null;
  if (fromKv && (!kvRegistry || !kvLearned)) throw new Error("--kv: the production registry could not be read");
  const registry: Registry = kvRegistry ? JSON.parse(kvRegistry) : existsSync(new URL("kit-registry.json", INTEL)) ? JSON.parse(readFileSync(new URL("kit-registry.json", INTEL), "utf8")) : { updated_at: "", families: [] };
  const learned: Family[] = kvLearned ? JSON.parse(kvLearned) : existsSync(new URL("learned-families.json", INTEL)) ? JSON.parse(readFileSync(new URL("learned-families.json", INTEL), "utf8")) : [];
  const index = indexFamilies({ updated_at: registry.updated_at, families: [...registry.families, ...learned] });
  const payTos = [...new Set(pays.map((p) => p.payTo))];
  const isPayTo = new Set(payTos);
  const payers = [...new Set(pays.map((p) => p.payer))];
  const everyone = [...new Set([...payTos, ...payers])];
  const watch = new Map<string, WatchEntry>();
  if (fromKv) {
    // The watch as production holds it now, for exactly these addresses (never the whole list).
    for (const [key, raw] of kvBulkGet(everyone.map((a) => `kw:a:${a}`))) {
      if (!raw) continue;
      const e = JSON.parse(raw) as WatchEntry;
      if (EOA_KINDS.has(e.k) || e.c === NETWORK) watch.set(key.slice(5), e);
    }
  } else {
    for (const f of ["watch-eip155-1.json", "watch-eip155-8453.json"]) {
      if (!existsSync(new URL(f, INTEL))) continue;
      for (const [a, e] of Object.entries(JSON.parse(readFileSync(new URL(f, INTEL), "utf8")) as Record<string, WatchEntry>)) if (EOA_KINDS.has(e.k) || e.c === NETWORK) watch.set(a, e);
    }
  }
  const facts = new Map<string, CodeFacts>();
  for (let i = 0; i < everyone.length; i += 50) {
    const chunk = everyone.slice(i, i + 50);
    const codes = await rpc.call(chunk.map((a) => ({ method: "eth_getCode", params: [a, "latest"] }))).catch(() => [] as unknown[]);
    chunk.forEach((a, k) => {
      if (typeof codes[k] === "string") facts.set(a, codeFacts(codes[k] as string));
    });
  }
  const indirect = new Map([...facts].filter(([, f]) => f.kind === "delegated" || f.kind === "delegating"));
  for (let i = 0; i < indirect.size; i += 100) await resolveIndirection(new Map([...indirect].slice(i, i + 100)), rpc.call, { maxLinks: Number.POSITIVE_INFINITY }).catch(() => undefined);
  const verdicts = new Map<string, Verdict>();
  let probes = 0;
  for (const a of everyone) {
    const flags: string[] = [];
    const subject = parseSubject(a);
    if (subject && screenSubject(subject).status === "listed") flags.push("ofac_sdn");
    if (feeds.scamsnifferAddresses?.set.has(a)) flags.push("scamsniffer_address");
    const w = watch.get(a);
    if (w) flags.push(`kit_watch:${w.k}`);
    const f = facts.get(a);
    const family = runningFamily(index, f);
    const kind: WatchKind | null = family && f ? kindForCode(family, f) : null;
    if (kind && !flags.includes(`kit_watch:${kind}`)) flags.push(`kit_watch_code:${kind}`);
    let delegateClass: string | undefined;
    // A delegated payee whose delegate no family knows: does it forward what it receives?
    if (f?.kind === "delegated" && !family && isPayTo.has(a) && probes < 200) {
      probes++;
      const probe = await probeForwarding(rpc.simulate, a);
      delegateClass = probe ? (probe.forwards ? "forwarder" : "keeps") : "unprobed";
      if (probe?.forwards) flags.push("forwards_incoming_eth");
    }
    verdicts.set(a, { flags, code: f ? f.kind : "unknown", ...(delegateClass ? { delegateClass } : {}) });
  }

  // --- aggregates ---
  const usdc = pays.filter((p) => p.token === USDC);
  const amounts = usdc.map((p) => p.amount).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const q = (p: number) => (amounts.length ? Number(amounts[Math.min(amounts.length - 1, Math.floor(p * amounts.length))]) / 1e6 : 0);
  const byPayTo = new Map<string, number>();
  for (const p of pays) byPayTo.set(p.payTo, (byPayTo.get(p.payTo) ?? 0) + 1);
  const top = [...byPayTo.values()].sort((x, y) => y - x);
  const classes = (list: string[]) =>
    list.reduce<Record<string, number>>((m, a) => {
      const f = facts.get(a);
      const k = !f ? "unknown" : f.kind === "none" ? "eoa" : f.kind === "delegated" ? "eip7702_delegated" : isContractCode(f) ? `contract:${f.kind}` : f.kind;
      m[k] = (m[k] ?? 0) + 1;
      return m;
    }, {});
  const flagged = (list: string[]) => list.filter((a) => (verdicts.get(a)?.flags.length ?? 0) > 0);
  const flagCounts = (list: string[]) => flagged(list).reduce<Record<string, number>>((m, a) => {
    for (const fl of verdicts.get(a)?.flags ?? []) m[fl] = (m[fl] ?? 0) + 1;
    return m;
  }, {});
  const flaggedPayTo = new Set(flagged(payTos));
  const flaggedPayer = new Set(flagged(payers));
  const report = {
    timestamp: new Date().toISOString(),
    facilitator,
    network: NETWORK,
    window_days: days,
    method: "settlement transactions sent by the facilitator's published signers (x402 v2 /supported), read from Blockscout; payments are their ERC-20 Transfer logs; checks are x402check's deterministic layers only (no model calls)",
    scamsniffer_addresses_as_of: feeds.scamsnifferAddresses?.as_of ?? null,
    kit_watch_source: fromKv ? "production KV at run time (registry, learned families, per-address watch entries)" : "local backfill snapshot (.cache/intel)",
    signers: { published: signers.length, active_on_base: active },
    settlement_transactions: txs.length,
    receipts_unavailable: failed,
    payments: pays.length,
    usdc_payments: usdc.length,
    usdc_volume: Math.round((Number(usdc.reduce((s, p) => s + p.amount, 0n)) / 1e6) * 100) / 100,
    usdc_amount_quantiles: { p10: q(0.1), p50: q(0.5), p90: q(0.9), p99: q(0.99) },
    payees: { distinct: payTos.length, code: classes(payTos), top10_share_of_payments: pays.length ? Math.round((top.slice(0, 10).reduce((s, n) => s + n, 0) / pays.length) * 1000) / 1000 : 0 },
    payers: { distinct: payers.length, code: classes(payers) },
    flags: {
      payees_flagged: flaggedPayTo.size,
      payee_flags: flagCounts(payTos),
      payers_flagged: flaggedPayer.size,
      payer_flags: flagCounts(payers),
      payments_to_flagged_payees: pays.filter((p) => flaggedPayTo.has(p.payTo)).length,
      payments_from_flagged_payers: pays.filter((p) => flaggedPayer.has(p.payer)).length,
      delegated_payees_probed: probes,
    },
    cost_if_every_payment_were_checked_usd: Math.round(pays.length * 0.001 * 100) / 100,
  };
  mkdirSync("eval/evidence", { recursive: true });
  writeFileSync(`eval/evidence/${arg("out", "payai-shadow-report.json")}`, JSON.stringify(report, null, 2));
  writeFileSync(new URL("payai-shadow-details.json", INTEL), JSON.stringify({ report, flagged: [...new Set([...flaggedPayTo, ...flaggedPayer])].map((a) => ({ address: a, payee: flaggedPayTo.has(a), payer: flaggedPayer.has(a), payments: pays.filter((p) => p.payTo === a || p.payer === a).length, ...verdicts.get(a) })) }, null, 1));
  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

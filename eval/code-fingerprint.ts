// Drainer-kit code fingerprints, externally grounded (no model calls).
//
// Recall — does a contract's logic code match a listed drainer's before its own
// address is listed? Measured three ways on ScamSniffer-listed contracts (Ethereum):
//   1. cross-source: fingerprints from Forta's 2023 phishing labels only (the set
//      embedded in the Worker) vs contracts ScamSniffer lists today;
//   2. temporal: each listed contract vs fingerprints of listed contracts created
//      BEFORE it (what a continuously updated set would have caught);
//   3. leave-one-out within ScamSniffer (upper bound; clusters may be listed together).
// False positives — collisions between the production fingerprint sets and the code
// of contracts real users call (the latest blocks) and of CoinGecko-listed tokens.
//
//   npx tsx eval/code-fingerprint.ts [--blocks 300]
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { codeFacts, fingerprintsOf, resolveIndirection, type CodeFacts } from "../src/code-fingerprint.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import { matchCode } from "../src/threat-intel.js";
import { FORTA_CODE_META } from "../src/data/code-feeds.js";
import { fetchCodes } from "../scripts/code-fetch.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { redactScamSniffer, scamSnifferOnly } from "./redact.js";
import { wilson } from "./stats.js";

const RPC = "https://ethereum-rpc.publicnode.com";
const BS = "https://eth.blockscout.com/api/v2";
const arg = (name: string, fallback: number): number => {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? Number(process.argv[i + 1]) : fallback;
};
const pct = (k: number, n: number) => {
  const w = wilson(k, n);
  const d = w.hi < 0.01 ? 3 : 1; // small upper bounds need more digits than "0.0%"
  return `${k}/${n} = ${(w.p * 100).toFixed(d)}% (95% CI ${(w.lo * 100).toFixed(d)}–${(w.hi * 100).toFixed(d)}%)`;
};

async function getJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await fetch(url, { ...init, headers: { accept: "application/json", "content-type": "application/json", "user-agent": "x402check-eval/0.3" }, signal: AbortSignal.timeout(30000) });
      if (res.status === 429) throw new Error("rate limited");
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
    }
  }
  return null;
}

/** Follows 7702 delegations, proxies and hard-coded links, as runtime matching does. */
async function resolveAll(entries: Map<string, CodeFacts>): Promise<void> {
  const call = async (requests: Array<{ method: string; params: unknown[] }>): Promise<unknown[]> => {
    const out: unknown[] = [];
    for (let i = 0; i < requests.length; i += 25) {
      const chunk = requests.slice(i, i + 25);
      const res = await getJson<Array<{ id: number; result?: unknown }>>(RPC, { method: "POST", body: JSON.stringify(chunk.map((r, k) => ({ jsonrpc: "2.0", id: k + 1, ...r }))) });
      const byId = new Map((res ?? []).map((r) => [r.id, r.result]));
      chunk.forEach((_, k) => out.push(byId.get(k + 1)));
    }
    return out;
  };
  const list = [...entries.entries()];
  // Every link of every contract, as a single-contract runtime lookup would follow them.
  for (let i = 0; i < list.length; i += 200) await resolveIndirection(new Map(list.slice(i, i + 200)), call, { maxLinks: Number.POSITIVE_INFINITY });
}

async function createdAt(address: string): Promise<number | null> {
  const info = await getJson<{ creation_transaction_hash?: string | null }>(`${BS}/addresses/${address}`);
  const hash = info?.creation_transaction_hash;
  if (!hash) return null;
  const tx = await getJson<{ timestamp?: string }>(`${BS}/transactions/${hash}`);
  return tx?.timestamp ? Date.parse(tx.timestamp) : null;
}

async function recentCallees(blocks: number): Promise<string[]> {
  const head = parseInt((await getJson<{ result: string }>(RPC, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }) }))?.result ?? "0x0", 16);
  const seen = new Set<string>();
  for (let b = head - blocks; b < head; b += 10) {
    const batch = Array.from({ length: Math.min(10, head - b) }, (_, i) => ({ jsonrpc: "2.0", id: i + 1, method: "eth_getBlockByNumber", params: [`0x${(b + i).toString(16)}`, true] }));
    const res = await getJson<Array<{ result?: { transactions?: Array<{ to?: string | null; input?: string }> } }>>(RPC, { method: "POST", body: JSON.stringify(batch) });
    for (const r of res ?? []) for (const tx of r.result?.transactions ?? []) if (tx.to && (tx.input ?? "0x").length > 2) seen.add(tx.to.toLowerCase());
  }
  return [...seen];
}

export async function runCodeFingerprintEval(opts: { blocks?: number } = {}): Promise<Record<string, unknown>> {
  const feeds = loadFeedsFromDisk();
  const cacheDir = new URL("../.cache/eval-sources/", import.meta.url);
  const file = readdirSync(cacheDir).find((f) => f.startsWith("scamsniffer-addresses"));
  if (!file) throw new Error("run eval/grounded.ts once to cache the ScamSniffer address list");
  const listed = [...new Set((JSON.parse(readFileSync(new URL(file, cacheDir), "utf8")) as string[]).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase()))];

  // --- recall on ScamSniffer-listed contracts (Ethereum) ---------------------------
  const { codes } = await fetchCodes(listed, RPC, { batch: 25 });
  const contracts = [...codes].map(([address, code]) => ({ address, facts: codeFacts(code) })).filter((c) => c.facts.kind !== "none" && c.facts.kind !== "delegated");
  // Own code only for recall: the sets are built from listed contracts' own logic code.
  const kinds = contracts.reduce<Record<string, number>>((m, c) => ((m[c.facts.kind] = (m[c.facts.kind] ?? 0) + 1), m), {});
  const fortaOnly = { fortaCode: feeds.fortaCode ?? null };
  const cross = contracts.filter((c) => c.facts.fingerprint && matchCode(fortaOnly, c.facts.fingerprint).length > 0);

  const byFp = new Map<string, string[]>();
  for (const c of contracts) if (c.facts.fingerprint) byFp.set(c.facts.fingerprint, [...(byFp.get(c.facts.fingerprint) ?? []), c.address]);
  const loo = contracts.filter((c) => c.facts.fingerprint && (byFp.get(c.facts.fingerprint) ?? []).length > 1);

  const dated: Array<{ address: string; facts: CodeFacts; at: number }> = [];
  for (const c of contracts) {
    const at = await createdAt(c.address);
    if (at !== null) dated.push({ ...c, at });
  }
  dated.sort((a, b) => a.at - b.at);
  const temporal = dated.filter((c, i) => c.facts.fingerprint && (dated.slice(0, i).some((p) => p.facts.fingerprint === c.facts.fingerprint) || matchCode(fortaOnly, c.facts.fingerprint).length > 0));

  // --- false positives on code real users call ------------------------------------
  const callees = await recentCallees(opts.blocks ?? 300);
  const tokens = ((await getJson<{ tokens: Array<{ address: string }> }>("https://tokens.coingecko.com/ethereum/all.json"))?.tokens ?? []).map((t) => t.address.toLowerCase());
  const corpus = [...new Set([...callees, ...tokens])].filter((a) => !listed.includes(a));
  const legit = (await fetchCodes(corpus, RPC, { batch: 25 })).codes;
  const legitFacts = [...legit].map(([address, code]) => ({ address, facts: codeFacts(code) })).filter((c) => c.facts.kind !== "none");
  // Runtime matching follows delegations, proxies and hard-coded links: so does this scan.
  await resolveAll(new Map(legitFacts.map((c) => [c.address, c.facts])));
  const legitKinds = legitFacts.reduce<Record<string, number>>((m, c) => ((m[c.facts.kind] = (m[c.facts.kind] ?? 0) + 1), m), {});
  const fingerprintable = legitFacts.filter((c) => fingerprintsOf(c.facts).length > 0);
  const hits = (c: { facts: CodeFacts }) => [...new Set(fingerprintsOf(c.facts).flatMap((fp) => matchCode(feeds, fp)))];
  const collisions = fingerprintable.filter((c) => hits(c).length > 0).map((c) => ({ address: c.address, kind: c.facts.kind, sources: hits(c) }));
  const viaIndirection = fingerprintable.filter((c) => !c.facts.fingerprint).length;

  return {
    timestamp: new Date().toISOString(),
    network: "eip155:1",
    fingerprint: "sha256 of runtime code minus the CBOR metadata trailer; token, NFT, delegating (DELEGATECALL/CALLCODE) and <100-byte code is never fingerprinted itself, but runtime matching follows 7702 delegations, proxies and hard-coded links to the code they run",
    sets: {
      forta: { as_of: FORTA_CODE_META.as_of, commit: FORTA_CODE_META.commit, fingerprints: FORTA_CODE_META.fingerprints },
      scamsniffer_runtime: feeds.scamsnifferCode ? { as_of: feeds.scamsnifferCode.as_of, fingerprints: feeds.scamsnifferCode.set.size } : "not built (run scripts/update-threat-feeds.ts --scamsniffer)",
    },
    recall: {
      scamsniffer_listed_addresses: listed.length,
      contracts_on_ethereum: contracts.length,
      code_kinds: kinds,
      cross_source_forta_2023: pct(cross.length, contracts.length),
      temporal_prior_listed_or_forta: { dated: dated.length, caught: pct(temporal.length, dated.length) },
      leave_one_out_upper_bound: pct(loo.length, contracts.length),
      caught_cross_source: cross.map((c) => c.address),
    },
    false_positives: {
      corpus: { recent_block_callees: callees.length, coingecko_tokens: tokens.length, blocks: opts.blocks ?? 300 },
      contracts: legitFacts.length,
      code_kinds: legitKinds,
      fingerprintable: fingerprintable.length,
      fingerprintable_via_delegation_or_proxy: viaIndirection,
      collisions: pct(collisions.length, fingerprintable.length),
      collisions_all_contracts: pct(collisions.length, legitFacts.length),
      collision_list: collisions,
    },
  };
}

async function main(): Promise<void> {
  const report = await runCodeFingerprintEval({ blocks: arg("blocks", 300) });
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  // ScamSniffer-only entries (GPL) are written as hashes: the report is committed.
  writeFileSync(`${EVAL_EVIDENCE_DIR}/code-fingerprint-report.json`, JSON.stringify(redactScamSniffer(report, await scamSnifferOnly()), null, 2));
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1]?.endsWith("code-fingerprint.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

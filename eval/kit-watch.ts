// Kit watch, externally grounded (no model calls). Reads what scripts/hunt-kits.ts found
// and measures it against labels and behaviour this project did not author:
//
//  1. Code precision: code that legitimate users run, held out from the collision gate
//     (verified contracts of pages 41–80, recent callees on Ethereum and Base), matching a
//     kit family (gated, and as it was before the gate) or a production code set. Every
//     match is printed for review.
//  2. Template recall (held-out, temporal): listed drainer contracts that an earlier
//     listed contract's code would have recognized at creation, exact vs template.
//  3. Poisoner audit: sampled authorities of the poisoner family confirmed as look-alikes
//     by a victim's history (a real counterparty sharing the first 3 and last 4 hex
//     digits; chance ≈ 4e-9 per pair). A lower bound: only recent history is read.
//  4. Forwarders and novelty: public labels of sweeper destinations, and how many
//     flagged addresses any public list names.
//
// The report holds aggregates only: the watchlist itself stays private.
//
//   npx tsx eval/kit-watch.ts [--sample 30] [--callee-blocks 300]
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { codeFacts, fingerprintsOf, type CodeFacts } from "../src/code-fingerprint.js";
import { indexFamilies, type Family, type FamilyIndex, type Registry, type WatchChain, type WatchEntry } from "../src/kit-watch.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import { matchCode } from "../src/threat-intel.js";
import { fetchCodes } from "../scripts/code-fetch.js";
import type { KitCatalog } from "../scripts/kit-catalog.js";
import { corpusFacts, recentCallees, verifiedPages, type LegitCorpus } from "../scripts/legit-corpus.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { sample, wilson } from "./stats.js";

const INTEL = new URL("../.cache/intel/", import.meta.url);
const RPC: Record<WatchChain, string> = { "eip155:1": "https://ethereum-rpc.publicnode.com", "eip155:8453": "https://base-rpc.publicnode.com" };
const BS: Record<WatchChain, string> = { "eip155:1": "https://eth.blockscout.com/api/v2", "eip155:8453": "https://base.blockscout.com/api/v2" };
const slug = (chain: string) => chain.replace(":", "-");
const arg = (name: string, fallback: number): number => {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? Number(process.argv[i + 1]) : fallback;
};
const pct = (k: number, n: number) => {
  const w = wilson(k, n);
  const d = w.hi < 0.01 ? 3 : 1;
  return `${k}/${n} = ${(w.p * 100).toFixed(d)}% (95% CI ${(w.lo * 100).toFixed(d)}–${(w.hi * 100).toFixed(d)}%)`;
};

async function getJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await fetch(url, { ...init, headers: { accept: "application/json", "content-type": "application/json", "user-agent": "x402check-eval/0.4" }, signal: AbortSignal.timeout(30000) });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
    }
  }
  return null;
}

function readIntel<T>(name: string, fallback: T): T {
  const file = new URL(name, INTEL);
  return existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as T) : fallback;
}

type Match = { address: string; family: string; class: Family["class"]; via: "own" | "implementation" | "linked"; by: "exact" | "template" };

function matchesOf(index: FamilyIndex, address: string, f: CodeFacts): Match[] {
  const out: Match[] = [];
  const test = (fp: string | undefined, sk: string | undefined, via: Match["via"]) => {
    const exact = fp ? index.exact.get(fp) : undefined;
    const template = !exact && sk ? index.skeleton.get(sk) : undefined;
    const fam = exact ?? template;
    if (fam) out.push({ address, family: fam.id, class: fam.class, via, by: exact ? "exact" : "template" });
  };
  test(f.fingerprint, f.skeleton, "own");
  test(f.implementation_fingerprint, f.implementation_skeleton, "implementation");
  for (const l of f.linked_fingerprints ?? []) test(l, undefined, "linked");
  return out;
}

/**
 * False positives on code legitimate users run, held out from the collision gate: the
 * verified contracts of pages 41–80 (scripts/legit-corpus.ts) and the contracts called in
 * the latest blocks. Measured for the gated families, the families as they were before the
 * gate, and the production code sets (Forta embedded, ScamSniffer runtime).
 */
async function precision(gated: FamilyIndex, ungated: FamilyIndex | null, legit: LegitCorpus, calleeBlocks: number, holdoutOverride?: Record<string, string[]>): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  const feeds = loadFeedsFromDisk();
  const review: string[] = [];
  for (const chain of ["eip155:1", "eip155:8453"] as WatchChain[]) {
    const blocks = chain === "eip155:1" ? calleeBlocks : calleeBlocks * 6; // same wall-clock window
    const holdout = (holdoutOverride ?? legit.holdout)[chain] ?? [];
    const callees = await recentCallees(chain, blocks);
    const facts = await corpusFacts(chain, [...new Set([...holdout, ...callees])]);
    const list = [...facts.entries()];
    const fingerprintable = list.filter(([, f]) => fingerprintsOf(f).length > 0).length;
    const kitHits = (index: FamilyIndex) => {
      const m = list.flatMap(([a, f]) => matchesOf(index, a, f)).filter((x) => x.class === "drainer_kit");
      return { matches: m, addresses: new Set(m.map((x) => x.address)).size };
    };
    const after = kitHits(gated);
    const before = ungated ? kitHits(ungated) : null;
    const listed = list.filter(([, f]) => fingerprintsOf(f).some((fp) => matchCode(feeds, fp).length > 0));
    for (const m of after.matches) review.push(`${chain} ${m.address} ${m.family} via ${m.via} by ${m.by}`);
    for (const [a] of listed) review.push(`${chain} ${a} production code set`);
    out[chain] = {
      corpus: { held_out_verified: holdout.length, recent_callees: callees.length, callee_blocks: blocks, with_code: facts.size, fingerprintable },
      kit_families_gated: pct(after.addresses, fingerprintable),
      ...(before ? { kit_families_before_gate: pct(before.addresses, fingerprintable) } : {}),
      production_code_sets: pct(listed.length, fingerprintable),
      // Poisoner and sweeper matches among callees are expected: their authorities are called.
      delegate_family_matches: list
        .flatMap(([a, f]) => matchesOf(gated, a, f))
        .filter((m) => m.class !== "drainer_kit")
        .reduce<Record<string, number>>((m, x) => ((m[`${x.class}:${x.by}`] = (m[`${x.class}:${x.by}`] ?? 0) + 1), m), {}),
    };
  }
  // Printed for review (private): every match in the held-out legitimate corpus.
  for (const r of review) console.error(`  review: ${r}`);
  return out;
}

async function recall(catalog: KitCatalog): Promise<Record<string, unknown>> {
  type Row = { address: string; chain: WatchChain; source: string; at: number; fp?: string; sk?: string };
  const rows: Row[] = [];
  for (const entry of Object.values(catalog.fingerprints)) {
    for (const m of entry.members) if (m.via === "own" && m.created_at) rows.push({ address: m.address, chain: m.chain as WatchChain, source: m.source, at: Date.parse(m.created_at) });
  }
  for (const chain of ["eip155:1", "eip155:8453"] as WatchChain[]) {
    const mine = rows.filter((r) => r.chain === chain);
    const { codes } = await fetchCodes(mine.map((r) => r.address), RPC[chain], { batch: 25 });
    for (const r of mine) {
      const f = codeFacts(codes.get(r.address) ?? "0x");
      if (f.fingerprint) r.fp = f.fingerprint;
      if (f.skeleton) r.sk = f.skeleton;
    }
  }
  rows.sort((a, b) => a.at - b.at);
  const targets = rows.filter((r) => r.source === "scamsniffer" && r.fp);
  let exact = 0;
  let template = 0;
  for (const r of targets) {
    const prior = rows.filter((p) => p.at < r.at && p.address !== r.address);
    const e = prior.some((p) => p.fp === r.fp);
    if (e) exact++;
    if (e || prior.some((p) => p.sk && p.sk === r.sk)) template++;
  }
  return {
    scope: "ScamSniffer-listed contracts with logic code (Ethereum, Base), each vs listed contracts (Forta or ScamSniffer) created before it",
    contracts: targets.length,
    exact: pct(exact, targets.length),
    exact_or_template: pct(template, targets.length),
  };
}

async function poisonerAudit(watch: Record<string, WatchEntry>, n: number): Promise<Record<string, unknown>> {
  const authorities = Object.entries(watch).filter(([, e]) => e.k === "poisoner_delegation").map(([a]) => a);
  const picked = sample(authorities.sort(), n, 7);
  // Wallets show the first and last hex digits: a look-alike shares at least 3 + 4 of them.
  const lookalike = (a: string, b: string) => a !== b && a.slice(2, 5) === b.slice(2, 5) && a.slice(-4) === b.slice(-4);
  type Party = { hash?: string } | null | undefined;
  const parties = async (address: string): Promise<string[]> => {
    const [tokens, txs] = await Promise.all([
      getJson<{ items?: Array<{ from?: Party; to?: Party }> }>(`${BS["eip155:1"]}/addresses/${address}/token-transfers`),
      getJson<{ items?: Array<{ from?: Party; to?: Party }> }>(`${BS["eip155:1"]}/addresses/${address}/transactions`),
    ]);
    return [...(tokens?.items ?? []), ...(txs?.items ?? [])].flatMap((t) => [t.from?.hash, t.to?.hash]).filter((x): x is string => !!x).map((x) => x.toLowerCase());
  };
  let confirmed = 0;
  let inactive = 0;
  for (const l of picked) {
    const victims = [...new Set((await parties(l)).filter((x) => x !== l))].slice(0, 8);
    if (!victims.length) {
      inactive++;
      continue;
    }
    let hit = false;
    for (const v of victims) {
      if ((await parties(v)).some((x) => lookalike(x, l))) {
        hit = true;
        break;
      }
    }
    if (hit) confirmed++;
  }
  const active = picked.length - inactive;
  return {
    authorities: authorities.length,
    sampled: picked.length,
    no_activity_yet: inactive,
    confirmed_lookalike: pct(confirmed, active),
    method: "among the latest 50 token transfers and 50 transactions of up to 8 counterparties of the authority, one is with a different address sharing the authority's first 3 and last 4 hex digits (the real payee it imitates); chance per pair ≈ 4e-9",
    by_construction: "the delegate obeys only its operator (tx.origin check in the verified source): while delegated, the operator controls the wallet whether or not it is a look-alike",
  };
}

async function forwarderAudit(watch: Record<WatchChain, Record<string, WatchEntry>>, listed: Set<string>): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const chain of Object.keys(watch) as WatchChain[]) {
    const entries = Object.entries(watch[chain]);
    const destinations = entries.filter(([, e]) => e.k === "sweeper_destination").map(([a]) => a);
    let labelled = 0;
    let scam = 0;
    let contracts = 0;
    const names: string[] = [];
    for (const d of destinations) {
      const info = await getJson<{ name?: string | null; is_contract?: boolean; is_scam?: boolean; reputation?: string; public_tags?: Array<{ display_name?: string }> }>(`${BS[chain]}/addresses/${d}`);
      if (info?.is_contract) contracts++;
      if (info?.is_scam || info?.reputation === "scam") scam++;
      const label = info?.name ?? info?.public_tags?.[0]?.display_name;
      if (label) {
        labelled++;
        names.push(label);
      }
    }
    out[chain] = {
      forwarding_delegations: entries.filter(([, e]) => e.k === "forwarding_delegation").length,
      sweeper_delegations: entries.filter(([, e]) => e.k === "sweeper_delegation").length,
      destinations: destinations.length,
      destinations_flagged_scam_by_explorer: scam,
      destinations_labelled: labelled,
      destination_labels: names,
      destinations_are_contracts: contracts,
      destinations_on_scamsniffer_list: destinations.filter((d) => listed.has(d)).length,
    };
  }
  return out;
}

export async function runKitWatchEval(opts: { sample: number; calleeBlocks: number }): Promise<Record<string, unknown>> {
  const registry = readIntel<Registry>("kit-registry.json", { updated_at: "", families: [] });
  const learned = readIntel<Family[]>("learned-families.json", []);
  const index = indexFamilies({ updated_at: registry.updated_at, families: [...registry.families, ...learned] });
  const catalog = readIntel<KitCatalog | null>("kit-catalog.json", null);
  if (!catalog || !registry.families.length) throw new Error("run scripts/kit-catalog.ts, scripts/kit-registry.ts and scripts/hunt-kits.ts first");
  const watch = {
    "eip155:1": readIntel<Record<string, WatchEntry>>(`watch-${slug("eip155:1")}.json`, {}),
    "eip155:8453": readIntel<Record<string, WatchEntry>>(`watch-${slug("eip155:8453")}.json`, {}),
  } as Record<WatchChain, Record<string, WatchEntry>>;
  const ssFile = new URL("../.cache/eval-sources/", import.meta.url);
  const ssName = readdirSync(ssFile).find((f) => f.startsWith("scamsniffer-addresses"));
  const listed = new Set<string>(ssName ? (JSON.parse(readFileSync(new URL(ssName, ssFile), "utf8")) as string[]).map((a) => String(a).toLowerCase()) : []);

  const volume: Record<string, unknown> = {};
  for (const chain of Object.keys(watch) as WatchChain[]) {
    const entries = Object.values(watch[chain]);
    const times = entries.map((e) => e.t).sort((a, b) => a - b);
    const hours = times.length ? Math.max(1, ((times[times.length - 1] as number) - (times[0] as number)) / 3600) : 0;
    volume[chain] = {
      addresses: entries.length,
      window_hours: Math.round(hours * 10) / 10,
      kinds: entries.reduce<Record<string, number>>((m, e) => ((m[e.k] = (m[e.k] ?? 0) + 1), m), {}),
      families: new Set(entries.map((e) => e.f)).size,
      on_scamsniffer_public_list: Object.keys(watch[chain]).filter((a) => listed.has(a)).length,
    };
  }
  const families = [...registry.families, ...learned].reduce<Record<string, number>>((m, f) => ((m[f.class] = (m[f.class] ?? 0) + 1), m), {});

  const legit = readIntel<LegitCorpus | null>("legit-corpus.json", null);
  if (!legit) throw new Error("run scripts/legit-corpus.ts first");
  const before = readIntel<Registry | null>("kit-registry-ungated.json", null);
  return {
    timestamp: new Date().toISOString(),
    registry: { families: registry.families.length + learned.length, by_class: families, templates: registry.families.filter((f) => f.skeleton.length).length, built_at: registry.updated_at },
    volume,
    code_precision: await precision(index, before ? indexFamilies(before) : null, legit, opts.calleeBlocks),
    template_recall: await recall(catalog),
    poisoner_precision: await poisonerAudit(watch["eip155:1"], opts.sample),
    forwarders: await forwarderAudit(watch, listed),
  };
}

/**
 * A second held-out measurement (verified pages 81–120 and fresh callees), for rules that
 * were derived from the first one: its result is independent of them.
 */
async function secondHoldout(calleeBlocks: number): Promise<Record<string, unknown>> {
  const registry = readIntel<Registry>("kit-registry.json", { updated_at: "", families: [] });
  const learned = readIntel<Family[]>("learned-families.json", []);
  const legit = readIntel<LegitCorpus | null>("legit-corpus.json", null);
  if (!legit) throw new Error("run scripts/legit-corpus.ts first");
  const override: Record<string, string[]> = {};
  for (const chain of ["eip155:1", "eip155:8453"] as WatchChain[]) {
    const pages = await verifiedPages(BS[chain], 120);
    override[chain] = pages.slice(80 * 50).map((v) => v.address);
  }
  return precision(indexFamilies({ updated_at: registry.updated_at, families: [...registry.families, ...learned] }), null, legit, calleeBlocks, override);
}

async function main(): Promise<void> {
  if (process.argv.includes("--second-holdout")) {
    const file = `${EVAL_EVIDENCE_DIR}/kit-watch-report.json`;
    const report = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    report.code_precision_second_holdout = { timestamp: new Date().toISOString(), scope: "verified contracts of pages 81–120 and fresh callees, after the rules derived from the first held-out run (pre-2021 Forta families, guarded fleets)", ...(await secondHoldout(arg("callee-blocks", 300))) };
    writeFileSync(file, JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report.code_precision_second_holdout, null, 2));
    return;
  }
  const report = await runKitWatchEval({ sample: arg("sample", 30), calleeBlocks: arg("callee-blocks", 300) });
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/kit-watch-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1]?.endsWith("kit-watch.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

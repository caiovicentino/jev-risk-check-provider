// Builds the kit-watch family registry (src/kit-watch.ts) from the kit catalog:
//
//  - drainer_kit: every fingerprint of the catalog (listed drainer contracts' own logic,
//    proxy implementations, hard-coded links), plus its template fingerprint;
//  - sweeper: delegates of listed EIP-7702 wallets that forward every wei they receive
//    (probed with eth_simulateV1 on a listed wallet that is still delegated);
//  - poisoner: publicly exposed address-poisoning executors (EXPOSED below).
//
// Guarded implementations (scripts/update-threat-feeds.ts) never enter a family, by
// exact or by template fingerprint. Neither does code in legitimate use: a family that
// collides with the reference corpus (scripts/legit-corpus.ts) is dropped, and so is any
// fingerprint that comes only from an address hard-coded in a listed contract (that
// target is whatever the contract calls: often a router or a token).
//
//   npx tsx scripts/kit-catalog.ts && npx tsx scripts/legit-corpus.ts && npx tsx scripts/kit-registry.ts [--upload]
//
// Output: .cache/intel/kit-registry.json. It holds ScamSniffer-derived data: private,
// never committed; --upload stores it in the Worker KV (binding RATE, key kw:registry).
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { codeFacts, resolveIndirection, type CodeFacts } from "../src/code-fingerprint.js";
import { probeForwarding, type Family, type Registry, type WatchChain } from "../src/kit-watch.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import { FORTA_SINCE, GUARDED_IMPLEMENTATIONS } from "./update-threat-feeds.js";
import { fetchCodes } from "./code-fetch.js";
import type { KitCatalog } from "./kit-catalog.js";
import type { LegitCorpus } from "./legit-corpus.js";

export const REGISTRY_KV_KEY = "kw:registry";
const INTEL = new URL("../.cache/intel/", import.meta.url);

/** Publicly exposed executors, with who exposed them. */
const EXPOSED: Array<{ id: string; chain: WatchChain; address: string; class: Family["class"]; sources: string[] }> = [
  // Verified by Wintermute with the source comment "used by bad guys for the address poisoning
  // scam"; Blockscout reputation "scam". Its template matches redeployments by other operators.
  { id: "poisoner-wintermute-exposed", chain: "eip155:1", address: "0xe6b97aa1490c93c28a14d86c13c9dc9c950643ed", class: "poisoner", sources: ["exposure:wintermute", "explorer:blockscout"] },
];

async function factsOf(chain: WatchChain, addresses: string[]): Promise<Map<string, CodeFacts>> {
  const rpc = kitWatchRpc(chain);
  const url = chain === "eip155:1" ? "https://ethereum-rpc.publicnode.com" : "https://base-rpc.publicnode.com";
  const { codes } = await fetchCodes(addresses, url, { batch: 20 });
  const facts = new Map([...codes].map(([a, c]) => [a, codeFacts(c)]));
  await resolveIndirection(facts, rpc.call, { maxLinks: Number.POSITIVE_INFINITY });
  return facts;
}

/** Exact and template fingerprints of the guarded implementations, on each chain they exist. */
async function guardedSets(): Promise<{ exact: Set<string>; skeleton: Set<string> }> {
  const exact = new Set<string>();
  const skeleton = new Set<string>();
  for (const chain of ["eip155:1", "eip155:8453"] as WatchChain[]) {
    const facts = await factsOf(chain, Object.values(GUARDED_IMPLEMENTATIONS).map((a) => a.toLowerCase()));
    for (const f of facts.values()) {
      if (f.fingerprint) exact.add(f.fingerprint);
      if (f.skeleton) skeleton.add(f.skeleton);
    }
  }
  if (exact.size < 5) throw new Error(`only ${exact.size} guarded fingerprints — RPC problem?`);
  return { exact, skeleton };
}

export async function buildRegistry(catalog: KitCatalog, legit: LegitCorpus): Promise<{ registry: Registry; report: Record<string, unknown> }> {
  const guarded = await guardedSets();
  // The collision gate: code in legitimate use, by exact or by template fingerprint.
  for (const fp of legit.fingerprints) guarded.exact.add(fp);
  for (const sk of legit.templates) guarded.skeleton.add(sk);
  const families: Family[] = [];
  const report: Record<string, unknown> = { drainer_kit: 0, sweeper: 0, sweeper_not_forwarding: [] as string[], guarded_dropped: 0, collided: [] as string[], linked_dropped: 0, exposed: 0 };

  // Current code of one or two members per fingerprint, per chain.
  const want = new Map<WatchChain, Set<string>>();
  for (const entry of Object.values(catalog.fingerprints)) {
    for (const m of entry.members.slice(0, 2)) {
      const chain = m.chain as WatchChain;
      want.set(chain, (want.get(chain) ?? new Set()).add(m.address));
    }
  }
  const facts = new Map<string, CodeFacts>();
  for (const [chain, set] of want) for (const [a, f] of await factsOf(chain, [...set])) facts.set(`${chain}|${a}`, f);

  for (const [fp, entry] of Object.entries(catalog.fingerprints)) {
    if (guarded.exact.has(fp)) {
      (report.guarded_dropped as number)++;
      if (legit.names[fp] !== undefined || legit.fingerprints.includes(fp)) (report.collided as string[]).push(`${fp.slice(0, 12)} = ${legit.names[fp] || "unnamed legitimate code"}`);
      continue;
    }
    // A hard-coded link names what the listed contract calls, not what it is.
    const own = entry.members.filter((m) => m.via !== "linked");
    if (!own.length) {
      (report.linked_dropped as number)++;
      continue;
    }
    // Forta's labels from before the drainer-kit era are mostly wallets and deposit contracts.
    if (own.every((m) => m.source === "forta" && (m.created_at ?? "9999") < FORTA_SINCE)) {
      report.forta_pre_2021_dropped = ((report.forta_pre_2021_dropped as number | undefined) ?? 0) + 1;
      continue;
    }
    const members = own.slice(0, 2);
    const first = members[0];
    if (!first) continue;
    const sources = entry.sources;
    const delegated = members.filter((m) => m.kind === "delegated");
    if (delegated.length === members.length) {
      // Delegates of listed wallets: a sweeper only if it forwards what the wallet receives.
      let forwards = false;
      for (const m of delegated) {
        const f = facts.get(`${m.chain}|${m.address}`);
        if (f?.kind !== "delegated" || f.implementation_fingerprint !== fp) continue;
        const probe = await probeForwarding(kitWatchRpc(m.chain as WatchChain).simulate, m.address);
        if (probe?.forwards) {
          forwards = true;
          break;
        }
      }
      if (!forwards) {
        (report.sweeper_not_forwarding as string[]).push(fp.slice(0, 12));
        continue;
      }
      families.push({ id: `sweeper-${fp.slice(0, 12)}`, class: "sweeper", exact: [fp], skeleton: [], sources: [...sources, "behaviour:auto-forward"] });
      (report.sweeper as number)++;
      continue;
    }
    // Drainer-kit logic: own code, a proxy's implementation, or a hard-coded link.
    const f = facts.get(`${first.chain}|${first.address}`);
    const sk = first.via === "own" ? f?.skeleton : f?.implementation_skeleton;
    const dates = entry.members.map((m) => m.created_at).filter((d): d is string => !!d).sort();
    families.push({
      id: `kit-${fp.slice(0, 12)}`,
      class: "drainer_kit",
      exact: [fp],
      skeleton: sk && !guarded.skeleton.has(sk) ? [sk] : [],
      sources,
      ...(dates[0] ? { first_seen: dates[0] } : {}),
    });
    (report.drainer_kit as number)++;
  }

  for (const e of EXPOSED) {
    const f = (await factsOf(e.chain, [e.address])).get(e.address);
    if (!f?.fingerprint || !f.skeleton) throw new Error(`exposed ${e.id}: no logic code at ${e.address}`);
    if (guarded.exact.has(f.fingerprint) || guarded.skeleton.has(f.skeleton)) throw new Error(`exposed ${e.id} collides with a guarded implementation`);
    families.push({ id: e.id, class: e.class, exact: [f.fingerprint], skeleton: [f.skeleton], sources: e.sources });
    (report.exposed as number)++;
  }

  // One template must not name two classes (a kit template equal to a sweeper's, say).
  const bySkeleton = new Map<string, Family>();
  for (const fam of families) {
    for (const sk of fam.skeleton) {
      const prev = bySkeleton.get(sk);
      if (prev && prev.class !== fam.class) throw new Error(`template ${sk.slice(0, 12)} names ${prev.id} and ${fam.id}`);
      bySkeleton.set(sk, fam);
    }
  }
  return { registry: { updated_at: new Date().toISOString(), families }, report };
}

async function main(): Promise<void> {
  const catalog = JSON.parse(readFileSync(new URL("kit-catalog.json", INTEL), "utf8")) as KitCatalog;
  const legit = JSON.parse(readFileSync(new URL("legit-corpus.json", INTEL), "utf8")) as LegitCorpus;
  const { registry, report } = await buildRegistry(catalog, legit);
  const file = new URL("kit-registry.json", INTEL);
  writeFileSync(file, JSON.stringify(registry));
  const classes = registry.families.reduce<Record<string, number>>((m, f) => ((m[f.class] = (m[f.class] ?? 0) + 1), m), {});
  console.log(JSON.stringify({ families: registry.families.length, classes, templates: registry.families.filter((f) => f.skeleton.length).length, ...report }, null, 1));
  if (process.argv.includes("--upload")) {
    execFileSync("npx", ["wrangler", "kv", "key", "put", REGISTRY_KV_KEY, "--path", fileURLToPath(file), "--binding", "RATE", "--remote", "--config", "deploy/wrangler.toml"], { stdio: "inherit" });
    console.log(`uploaded ${REGISTRY_KV_KEY}`);
  }
}

if (process.argv[1]?.endsWith("kit-registry.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

// Builds the drainer-kit catalog: every listed drainer contract on Ethereum and Base
// whose logic code is fingerprintable (own code, or the code it delegates/forwards to),
// with how and by whom it was created. The kit hunter (scripts/hunt-kits.ts) matches new
// deployments against it and reports which kit, which listed sibling and which deployer.
//
//   npx tsx scripts/kit-catalog.ts            → .cache/intel/kit-catalog.json (private)
//
// Sources: Forta labelled-datasets (MIT, cached by eval/grounded.ts) and ScamSniffer
// (GPL-3.0). The catalog holds ScamSniffer-derived data, so it lives in .cache only:
// never committed, never bundled.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { codeFacts, resolveIndirection, type CodeFacts } from "../src/code-fingerprint.js";
import { fetchCodes } from "./code-fetch.js";
import { guardedFingerprints } from "./update-threat-feeds.js";

export const CHAINS = {
  "eip155:1": { rpc: "https://ethereum-rpc.publicnode.com", blockscout: "https://eth.blockscout.com/api/v2" },
  "eip155:8453": { rpc: "https://base-rpc.publicnode.com", blockscout: "https://base.blockscout.com/api/v2" },
} as const;
export type Chain = keyof typeof CHAINS;

export type CatalogMember = {
  address: string;
  chain: Chain;
  source: "forta" | "scamsniffer";
  kind: CodeFacts["kind"];
  /** Whose code identifies the kit: the contract's own logic, or its delegate / implementation / hard-coded link. */
  via: "own" | "implementation" | "linked";
  created_at?: string;
  creation?: "top" | "internal";
  /** The EOA that sent the creating transaction. */
  deployer?: string;
  /** The contract the creating transaction called, for internal creations. */
  factory?: string;
  tx?: string;
};
export type KitCatalog = {
  built_at: string;
  fingerprints: Record<string, { sources: string[]; members: CatalogMember[] }>;
};

const CACHE = new URL("../.cache/", import.meta.url);

export async function getJson<T>(url: string, init?: RequestInit, tries = 4): Promise<T | null> {
  for (let attempt = 0; attempt < tries; attempt++) {
    try {
      const res = await fetch(url, { ...init, headers: { accept: "application/json", "content-type": "application/json", "user-agent": "x402check-intel/0.4" }, signal: AbortSignal.timeout(30000) });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
    }
  }
  return null;
}

/** Runs `fn` over `items` with bounded concurrency, preserving order. */
export async function pool<T, R>(items: T[], concurrency: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i] as T, i);
      }
    }),
  );
  return out;
}

export function batchCall(rpc: string) {
  return async (requests: Array<{ method: string; params: unknown[] }>): Promise<unknown[]> => {
    const out: unknown[] = [];
    for (let i = 0; i < requests.length; i += 20) {
      const chunk = requests.slice(i, i + 20);
      const res = await getJson<Array<{ id: number; result?: unknown }>>(rpc, { method: "POST", body: JSON.stringify(chunk.map((r, k) => ({ jsonrpc: "2.0", id: k + 1, ...r }))) });
      const byId = new Map((Array.isArray(res) ? res : []).map((r) => [r.id, r.result]));
      chunk.forEach((_, k) => out.push(byId.get(k + 1)));
    }
    return out;
  };
}

/** How a contract was created, from Blockscout: top-level (to = null) or by a factory; the EOA behind it. */
export async function creationOf(chain: Chain, address: string): Promise<Pick<CatalogMember, "created_at" | "creation" | "deployer" | "factory" | "tx"> | null> {
  const bs = CHAINS[chain].blockscout;
  const info = await getJson<{ creation_transaction_hash?: string | null; creator_address_hash?: string | null }>(`${bs}/addresses/${address}`);
  const hash = info?.creation_transaction_hash;
  if (!hash) return null;
  const tx = await getJson<{ timestamp?: string; from?: { hash?: string }; to?: { hash?: string } | null }>(`${bs}/transactions/${hash}`);
  if (!tx) return null;
  const to = tx.to?.hash?.toLowerCase();
  const deployer = tx.from?.hash?.toLowerCase();
  return {
    ...(tx.timestamp ? { created_at: tx.timestamp } : {}),
    creation: to ? "internal" : "top",
    ...(deployer ? { deployer } : {}),
    ...(to ? { factory: to } : {}),
    tx: hash,
  };
}

function listed(): Array<{ address: string; source: CatalogMember["source"] }> {
  const dir = new URL("eval-sources/", CACHE);
  const ssFile = readdirSync(dir).find((f) => f.startsWith("scamsniffer-addresses"));
  if (!ssFile) throw new Error("run eval/grounded.ts once to cache the ScamSniffer address list");
  const ss = (JSON.parse(readFileSync(new URL(ssFile, dir), "utf8")) as string[]).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase());
  const forta = readFileSync(new URL("forta/phishing_scams.csv", dir), "utf8")
    .trim()
    .split("\n")
    .slice(1)
    .map((l) => l.split(","))
    .filter((r) => r[3] === "True" && /^0x[0-9a-fA-F]{40}$/.test(r[0] ?? ""))
    .map((r) => (r[0] as string).toLowerCase());
  const out = new Map<string, CatalogMember["source"]>();
  for (const a of forta) out.set(a, "forta");
  for (const a of ss) if (!out.has(a)) out.set(a, "scamsniffer");
  return [...out].map(([address, source]) => ({ address, source }));
}

export async function buildCatalog(): Promise<KitCatalog> {
  const all = listed();
  const guarded = await guardedFingerprints();
  const fingerprints: KitCatalog["fingerprints"] = {};
  for (const chain of Object.keys(CHAINS) as Chain[]) {
    const { rpc } = CHAINS[chain];
    const { codes, failedBatches } = await fetchCodes(all.map((l) => l.address), rpc, { batch: 20 });
    const facts = new Map<string, CodeFacts>();
    for (const [address, code] of codes) {
      const f = codeFacts(code);
      if (f.kind !== "none") facts.set(address, f);
    }
    await resolveIndirection(facts, batchCall(rpc), { maxLinks: Number.POSITIVE_INFINITY });
    const members: Array<{ fp: string; m: CatalogMember }> = [];
    for (const [address, f] of facts) {
      const source = all.find((l) => l.address === address)?.source ?? "scamsniffer";
      const add = (fp: string | undefined, via: CatalogMember["via"]) => {
        if (fp && !guarded.has(fp)) members.push({ fp, m: { address, chain, source, kind: f.kind, via } });
      };
      add(f.fingerprint, "own");
      add(f.implementation_fingerprint, "implementation");
      for (const l of f.linked_fingerprints ?? []) add(l, "linked");
    }
    console.log(`${chain}: ${codes.size}/${all.length} answered (${failedBatches} failed batches), ${facts.size} with code, ${members.length} fingerprinted members`);
    const created = await pool(members, 4, async ({ m }) => creationOf(chain, m.address));
    members.forEach(({ fp, m }, i) => {
      const entry = (fingerprints[fp] ??= { sources: [], members: [] });
      entry.members.push({ ...m, ...(created[i] ?? {}) });
      if (!entry.sources.includes(m.source)) entry.sources.push(m.source);
    });
  }
  return { built_at: new Date().toISOString(), fingerprints };
}

async function main(): Promise<void> {
  const catalog = await buildCatalog();
  mkdirSync(new URL("intel/", CACHE), { recursive: true });
  writeFileSync(new URL("intel/kit-catalog.json", CACHE), JSON.stringify(catalog, null, 1));
  const members = Object.values(catalog.fingerprints).flatMap((e) => e.members);
  const count = <K extends string>(key: (m: CatalogMember) => K | undefined) =>
    members.reduce<Record<string, number>>((acc, m) => ((acc[key(m) ?? "unknown"] = (acc[key(m) ?? "unknown"] ?? 0) + 1), acc), {});
  const deployers = count((m) => m.deployer);
  const factories = count((m) => m.factory);
  console.log(
    JSON.stringify(
      {
        fingerprints: Object.keys(catalog.fingerprints).length,
        members: members.length,
        by_chain: count((m) => m.chain),
        by_via: count((m) => m.via),
        by_kind: count((m) => m.kind),
        by_creation: count((m) => m.creation),
        by_source: count((m) => m.source),
        deployers: { distinct: Object.keys(deployers).length, reused: Object.values(deployers).filter((n) => n > 1).length, top: Object.entries(deployers).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([, n]) => n) },
        factories: { distinct: Object.keys(factories).length - (factories.unknown ? 1 : 0), top: Object.entries(factories).filter(([k]) => k !== "unknown").sort((a, b) => b[1] - a[1]).slice(0, 8).map(([, n]) => n) },
        years: count((m) => m.created_at?.slice(0, 4)),
      },
      null,
      1,
    ),
  );
}

if (process.argv[1]?.endsWith("kit-catalog.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

// Reference corpus of code that legitimate users run, for the collision gate.
//
// A drainer list can name a contract whose code is shared by a legitimate fleet: the
// Forta dataset labels 11 Luno deposit forwarders and a Poloniex deposit contract as
// phishing (they received phishing proceeds), and their code is the exchange's standard
// deposit contract. A fingerprint that matches code in legitimate use must never enter
// a drainer set or a kit family, whatever the list says.
//
//   npx tsx scripts/legit-corpus.ts   → .cache/intel/legit-corpus.json
//
// Sources, per chain (Ethereum, Base):
//   - the most recently verified contracts on Blockscout: pages 1–40 form the gate, pages
//     41–80 are held out for eval/kit-watch.ts (so its precision is not measured on the
//     data that built the gate);
//   - CoinGecko's token list, and the implementations behind token proxies;
//   - the contracts called in the latest blocks (Ethereum 300, Base 900).
import { mkdirSync, writeFileSync } from "node:fs";
import { codeFacts, resolveIndirection, type CodeFacts } from "../src/code-fingerprint.js";
import { kitWatchRpc } from "../src/kit-watch-rpc.js";
import type { WatchChain } from "../src/kit-watch.js";
import { fetchCodes } from "./code-fetch.js";
import { getJson } from "./kit-catalog.js";

const INTEL = new URL("../.cache/intel/", import.meta.url);
export const CORPUS_CHAINS: Record<WatchChain, { rpc: string; blockscout: string; coingecko: string; calleeBlocks: number }> = {
  "eip155:1": { rpc: "https://ethereum-rpc.publicnode.com", blockscout: "https://eth.blockscout.com/api/v2", coingecko: "https://tokens.coingecko.com/ethereum/all.json", calleeBlocks: 300 },
  "eip155:8453": { rpc: "https://base-rpc.publicnode.com", blockscout: "https://base.blockscout.com/api/v2", coingecko: "https://tokens.coingecko.com/base/all.json", calleeBlocks: 900 },
};
const GATE_PAGES = 40;
const HOLDOUT_PAGES = 40;

export type LegitCorpus = {
  built_at: string;
  /** Exact logic fingerprints and template fingerprints of the gate corpus (own code and implementations). */
  fingerprints: string[];
  templates: string[];
  /** fingerprint → a verified name that runs it (for reports). */
  names: Record<string, string>;
  /** Held-out verified contracts, for evaluation only. */
  holdout: Record<string, string[]>;
  sizes: Record<string, Record<string, number>>;
};

/** Verified contracts, newest first: `pages` pages of 50, with their names. */
export async function verifiedPages(blockscout: string, pages: number): Promise<Array<{ address: string; name: string }>> {
  const out: Array<{ address: string; name: string }> = [];
  let params = "";
  for (let p = 0; p < pages; p++) {
    const page = await getJson<{ items?: Array<{ address?: { hash?: string }; name?: string }>; next_page_params?: Record<string, unknown> | null }>(`${blockscout}/smart-contracts${params}`);
    for (const it of page?.items ?? []) if (it.address?.hash) out.push({ address: it.address.hash.toLowerCase(), name: it.name ?? "" });
    if (!page?.next_page_params) break;
    params = `?${new URLSearchParams(Object.entries(page.next_page_params).map(([k, v]): [string, string] => [k, String(v)])).toString()}`;
  }
  return out;
}

/** Contracts called with calldata in the latest `blocks` blocks. */
export async function recentCallees(chain: WatchChain, blocks: number): Promise<string[]> {
  const rpc = kitWatchRpc(chain, { timeoutMs: 45000 });
  const head = (await rpc.head()) - 5;
  const seen = new Set<string>();
  for (let b = head - blocks; b < head; b += 50) {
    for (const block of await rpc.blocks(b, Math.min(head - 1, b + 49))) {
      for (const tx of block.transactions) if (typeof tx !== "string" && tx.to && ((tx as { input?: string }).input ?? "0x").length > 2) seen.add(tx.to.toLowerCase());
    }
  }
  return [...seen];
}

/** Code facts of `addresses`, following delegations and proxies (every hard-coded link too). */
export async function corpusFacts(chain: WatchChain, addresses: string[]): Promise<Map<string, CodeFacts>> {
  const { codes } = await fetchCodes(addresses, CORPUS_CHAINS[chain].rpc, { batch: 25 });
  const facts = new Map([...codes].map(([a, c]) => [a, codeFacts(c)] as const).filter(([, f]) => f.kind !== "none"));
  const rpc = kitWatchRpc(chain, { timeoutMs: 45000 });
  const list = [...facts.entries()];
  for (let i = 0; i < list.length; i += 200) await resolveIndirection(new Map(list.slice(i, i + 200)), rpc.call, { maxLinks: Number.POSITIVE_INFINITY });
  return facts;
}

export async function buildLegitCorpus(): Promise<LegitCorpus> {
  const fingerprints = new Set<string>();
  const templates = new Set<string>();
  const names: Record<string, string> = {};
  const holdout: Record<string, string[]> = {};
  const sizes: Record<string, Record<string, number>> = {};
  for (const [chain, c] of Object.entries(CORPUS_CHAINS) as Array<[WatchChain, (typeof CORPUS_CHAINS)[WatchChain]]>) {
    const [verified, tokens, callees] = await Promise.all([
      verifiedPages(c.blockscout, GATE_PAGES + HOLDOUT_PAGES),
      getJson<{ tokens: Array<{ address: string }> }>(c.coingecko).then((j) => (j?.tokens ?? []).map((t) => t.address.toLowerCase())),
      recentCallees(chain, c.calleeBlocks),
    ]);
    const gateVerified = verified.slice(0, GATE_PAGES * 50);
    holdout[chain] = verified.slice(GATE_PAGES * 50).map((v) => v.address);
    const nameOf = new Map(gateVerified.map((v) => [v.address, v.name]));
    const facts = await corpusFacts(chain, [...new Set([...gateVerified.map((v) => v.address), ...tokens, ...callees])]);
    for (const [address, f] of facts) {
      for (const [fp, sk] of [
        [f.fingerprint, f.skeleton],
        [f.implementation_fingerprint, f.implementation_skeleton],
      ] as const) {
        if (fp) {
          fingerprints.add(fp);
          const name = nameOf.get(address);
          if (name && !names[fp]) names[fp] = name;
        }
        if (sk) templates.add(sk);
      }
    }
    sizes[chain] = { verified_gate: gateVerified.length, verified_holdout: holdout[chain].length, tokens: tokens.length, callees: callees.length, with_code: facts.size };
    console.log(`${chain}: ${JSON.stringify(sizes[chain])}`);
  }
  return { built_at: new Date().toISOString(), fingerprints: [...fingerprints], templates: [...templates], names, holdout, sizes };
}

async function main(): Promise<void> {
  const corpus = await buildLegitCorpus();
  mkdirSync(INTEL, { recursive: true });
  writeFileSync(new URL("legit-corpus.json", INTEL), JSON.stringify(corpus));
  console.log(`legit corpus: ${corpus.fingerprints.length} logic fingerprints, ${corpus.templates.length} templates`);
}

if (process.argv[1]?.endsWith("legit-corpus.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

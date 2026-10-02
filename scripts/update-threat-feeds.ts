// Rebuilds the community threat feeds used by the provider.
//
//   npx tsx scripts/update-threat-feeds.ts                 # MetaMask list → src/data (embedded, committed)
//   npx tsx scripts/update-threat-feeds.ts --scamsniffer   # + ScamSniffer → .cache/threat-feeds (never committed)
//   npx tsx scripts/update-threat-feeds.ts --scamsniffer --upload   # + upload ScamSniffer blobs to the Worker KV
//   npx tsx scripts/update-threat-feeds.ts --forta         # + Forta drainer-code fingerprints → src/data (embedded, committed)
//
// Code fingerprints (src/code-fingerprint.ts) are built from the runtime code of listed
// contracts: Forta labelled-datasets (MIT; Ethereum) and ScamSniffer addresses (fetched
// on every chain with a default public RPC).
//
// Licensing: MetaMask eth-phishing-detect is DBAD-1.2 (derived work with attribution,
// see THIRD_PARTY_NOTICES.md). ScamSniffer scam-database is GPL-3.0, so its derived
// blobs are only stored in the operator's KV and read at runtime; they are never
// committed to this MIT repository or bundled into the Worker.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { neverFlag } from "../src/never-flag.js";
import { buildHashBlob, normalizeFeedDomain } from "../src/threat-intel.js";
import { SCAMSNIFFER_KEYS as KV_KEYS } from "../deploy/scamsniffer-refresh.js";
import { codeFacts } from "../src/code-fingerprint.js";
import { fetchCodes } from "./code-fetch.js";
import { creationOf, pool } from "./kit-catalog.js";

// Every list is read at the head commit resolved first, so the recorded commit is the data's.
const MM_REPO = "MetaMask/eth-phishing-detect";
const MM_CONFIG = (sha: string) => `https://raw.githubusercontent.com/${MM_REPO}/${sha}/src/config.json`;
const SS_REPO = "scamsniffer/scam-database";
const SS_LIST = (sha: string, file: "domains.json" | "address.json") => `https://raw.githubusercontent.com/${SS_REPO}/${sha}/blacklist/${file}`;
const DATA = new URL("../src/data/", import.meta.url);
const CACHE = new URL("../.cache/threat-feeds/", import.meta.url);
// One definition of the KV keys, shared with the Worker (loader and cron refresh).
export { KV_KEYS };
const FORTA_REPO = "forta-network/labelled-datasets";
// Bulk eth_getCode endpoints: the default RPCs of Base and Optimism cap batches at 10 calls.
const BULK_RPC: Record<string, string> = {
  "eip155:1": "https://ethereum-rpc.publicnode.com",
  "eip155:8453": "https://base-rpc.publicnode.com",
  "eip155:56": "https://bsc-rpc.publicnode.com",
  "eip155:137": "https://polygon-bor-rpc.publicnode.com",
  "eip155:42161": "https://arbitrum-one-rpc.publicnode.com",
  "eip155:10": "https://optimism-rpc.publicnode.com",
  "eip155:43114": "https://avalanche-c-chain-rpc.publicnode.com",
};
const FORTA_PHISHING = (sha: string) => `https://raw.githubusercontent.com/${FORTA_REPO}/${sha}/labels/1/phishing_scams.csv`;

/**
 * Implementations that countless legitimate accounts run (EIP-7702 delegates, Safe
 * singletons, smart-wallet and 4337 infrastructure, core DeFi entry points). Runtime
 * matching follows delegations and proxies to their implementation, so a listed clone
 * of any of these must never enter a drainer set: it would flag every user of the
 * original. Their fingerprints are removed at build time.
 */
export const GUARDED_IMPLEMENTATIONS: Record<string, string> = {
  "MetaMask EIP7702StatelessDeleGator": "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B",
  "Safe 1.4.1": "0x41675C099F32341bf84BFc5382aF534df5C7461a",
  "SafeL2 1.4.1": "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
  "GnosisSafe 1.3.0": "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
  "GnosisSafeL2 1.3.0": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E",
  "Coinbase Smart Wallet": "0x000100abaad02f1cfC8Bbe32bD5a564817339E72",
  "EntryPoint v0.7": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  "EntryPoint v0.6": "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
  "Permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
  "Multicall3": "0xcA11bde05977b3631167028862bE2a173976CA11",
  "Uniswap Universal Router v2": "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
  // Exchange deposit fleets. Lists label single deposit addresses as phishing (they received
  // phishing proceeds), but the code is the operator's standard deposit contract, shared by
  // every customer's deposit address (found by eval/kit-watch.ts; see docs/EVIDENCE.md).
  "BitGo Forwarder (eth-multisig-v2, solc 0.4.16)": "0x95115419b09e8cea70a9bdbca3fee8c5e118b228",
  "LunoDepositForwarder": "0xea21d5ac9cbd3b84e00da63e610025577b87cea1",
  "PoloniexDeposit": "0x4700269d287699792e45026b6529f215ada9952c",
  "Ethereum Wallet multisig (Mist, solc 0.3.2)": "0x9b6f6b23f3fa2dcaea92194033a69840f398f8c4",
};

/**
 * Forta labels contracts from before the drainer-kit era (2017–2020) that are mostly
 * wallets and deposit contracts that received scam proceeds: every collision measured
 * with legitimate code came from one of them, and none of them recognized a later listed
 * drainer. Only contracts created from this date on seed a Forta code set.
 */
export const FORTA_SINCE = "2021-01-01";

/** Fingerprints of GUARDED_IMPLEMENTATIONS (Ethereum). */
export async function guardedFingerprints(): Promise<Map<string, string>> {
  const addresses = Object.values(GUARDED_IMPLEMENTATIONS).map((a) => a.toLowerCase());
  const { codes } = await fetchCodes(addresses, BULK_RPC["eip155:1"] as string, { batch: 20 });
  const out = new Map<string, string>();
  for (const [name, address] of Object.entries(GUARDED_IMPLEMENTATIONS)) {
    const fp = codeFacts(codes.get(address.toLowerCase()) ?? "0x").fingerprint;
    if (fp) out.set(fp, name);
  }
  if (out.size < 5) throw new Error(`only ${out.size} guarded implementations fingerprinted — RPC problem?`);
  return out;
}

/**
 * The collision gate (scripts/legit-corpus.ts): fingerprints of code in legitimate use.
 * Lists name contracts whose code is shared by a legitimate fleet (Forta labels Luno and
 * Poloniex deposit contracts as phishing), so a set is never built without it.
 */
export function legitFingerprints(): { set: Set<string>; names: Record<string, string> } {
  const file = new URL("../.cache/intel/legit-corpus.json", import.meta.url);
  if (!existsSync(file)) throw new Error("run scripts/legit-corpus.ts first: code sets are gated against legitimate code");
  const corpus = JSON.parse(readFileSync(file, "utf8")) as { fingerprints: string[]; names: Record<string, string> };
  return { set: new Set(corpus.fingerprints), names: corpus.names };
}

/**
 * Logic-code fingerprints of the listed addresses that are contracts on the given
 * chains. Returns fingerprints plus per-kind counts (tokens, proxies, ... are skipped).
 */
export async function codeFingerprints(addresses: string[], networks: string[]): Promise<{ fingerprints: Set<string>; kinds: Record<string, number>; chains: Record<string, { contracts: number; failed_batches: number }> }> {
  const fingerprints = new Set<string>();
  const kinds: Record<string, number> = {};
  const chains: Record<string, { contracts: number; failed_batches: number }> = {};
  // Chains in parallel (one RPC each), batches sequential within a chain.
  const fetched = await Promise.all(networks.filter((n) => BULK_RPC[n]).map(async (network) => ({ network, ...(await fetchCodes(addresses, BULK_RPC[network] as string, { batch: 20 })) })));
  for (const { network, codes, failedBatches } of fetched) {
    let contracts = 0;
    for (const code of codes.values()) {
      const f = codeFacts(code);
      if (f.kind === "none") continue;
      contracts++;
      kinds[f.kind] = (kinds[f.kind] ?? 0) + 1;
      if (f.fingerprint) fingerprints.add(f.fingerprint);
    }
    chains[network] = { contracts, failed_batches: failedBatches };
    console.log(`  ${network}: ${codes.size}/${addresses.length} answered, ${contracts} with code, ${failedBatches} failed batches`);
  }
  const guarded = await guardedFingerprints();
  const legit = legitFingerprints();
  for (const fp of [...fingerprints]) {
    if (guarded.has(fp)) {
      fingerprints.delete(fp);
      kinds.guarded_removed = (kinds.guarded_removed ?? 0) + 1;
      console.log(`  removed a listed fingerprint identical to ${guarded.get(fp)}`);
    } else if (legit.set.has(fp)) {
      fingerprints.delete(fp);
      kinds.legit_collision_removed = (kinds.legit_collision_removed ?? 0) + 1;
      console.log(`  removed a listed fingerprint in legitimate use (${legit.names[fp] || "unnamed"})`);
    }
  }
  return { fingerprints, kinds, chains };
}

async function getJson<T>(url: string): Promise<{ body: T; sha256: string }> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const text = await res.text();
  return { body: JSON.parse(text) as T, sha256: createHash("sha256").update(text).digest("hex") };
}

async function headCommit(repo: string): Promise<{ sha: string; date: string }> {
  const res = await fetch(`https://api.github.com/repos/${repo}/commits/main`, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) throw new Error(`${repo} commit lookup: HTTP ${res.status}`);
  const c = (await res.json()) as { sha: string; commit: { committer: { date: string } } };
  // The SHA becomes part of the list URLs.
  if (!/^[0-9a-f]{40}$/.test(c.sha)) throw new Error(`${repo} commit lookup: unexpected sha`);
  return { sha: c.sha, date: c.commit.committer.date.slice(0, 10) };
}

export { normalizeFeedDomain };

async function metamask(): Promise<void> {
  const commit = await headCommit(MM_REPO);
  const { body, sha256 } = await getJson<{ blacklist?: string[]; whitelist?: string[]; fuzzylist?: string[] }>(MM_CONFIG(commit.sha));
  const black = (body.blacklist ?? []).map(normalizeFeedDomain);
  const hosts = black.filter((h): h is string => h !== null);
  const skipped = black.length - hosts.length;
  const allow = [...new Set((body.whitelist ?? []).map(normalizeFeedDomain).filter((h): h is string => h !== null))].sort();
  const blob = buildHashBlob(hosts);
  if (blob.byteLength / 8 < 10_000) throw new Error(`only ${blob.byteLength / 8} MetaMask entries — format changed?`);
  writeFileSync(new URL("metamask-phishing.bin", DATA), blob);
  const meta = {
    source: `https://github.com/${MM_REPO}`,
    license: "DBAD-1.2 (derived hash set, attributed in THIRD_PARTY_NOTICES.md)",
    commit: commit.sha,
    as_of: commit.date,
    entries: blob.byteLength / 8,
    skipped_path_or_invalid: skipped,
    config_sha256: sha256,
  };
  writeFileSync(
    new URL("threat-feeds.ts", DATA),
    [
      "// GENERATED by scripts/update-threat-feeds.ts — do not edit by hand.",
      "// MetaMask eth-phishing-detect blacklist, stored as sorted SHA-256 prefixes in metamask-phishing.bin.",
      `export const METAMASK_FEED_META = ${JSON.stringify(meta)} as const;`,
      "",
      "/** Hosts MetaMask's own list allowlists (feed-normalized). */",
      `export const METAMASK_ALLOWLIST: readonly string[] = ${JSON.stringify(allow)};`,
      "",
    ].join("\n"),
  );
  console.log(`MetaMask ${commit.date} (${commit.sha.slice(0, 7)}): ${meta.entries} hosts, ${allow.length} allowlisted, ${skipped} path/invalid skipped`);
}

async function forta(): Promise<void> {
  const commit = await headCommit(FORTA_REPO);
  const res = await fetch(FORTA_PHISHING(commit.sha));
  if (!res.ok) throw new Error(`forta phishing_scams.csv: HTTP ${res.status}`);
  const rows = (await res.text()).trim().split("\n").slice(1).map((l) => l.split(","));
  const listed = [...new Set(rows.filter((r) => r[3] === "True" && /^0x[0-9a-fA-F]{40}$/.test(r[0] ?? "")).map((r) => (r[0] as string).toLowerCase()))];
  // Creation dates (Blockscout): contracts from before FORTA_SINCE are left out (see there).
  const created = await pool(listed, 4, async (a) => (await creationOf("eip155:1", a))?.created_at);
  const undated = created.filter((d) => !d).length;
  if (undated > listed.length / 10) throw new Error(`${undated} of ${listed.length} creation dates unavailable — Blockscout problem?`);
  const contracts = listed.filter((_, i) => (created[i] ?? "9999") >= FORTA_SINCE);
  console.log(`  Forta: ${listed.length} listed contracts, ${contracts.length} created since ${FORTA_SINCE} (${undated} undated, kept)`);
  const { fingerprints, kinds, chains } = await codeFingerprints(contracts, ["eip155:1"]);
  const blob = buildHashBlob(fingerprints);
  writeFileSync(new URL("forta-drainer-code.bin", DATA), blob);
  const meta = {
    source: `https://github.com/${FORTA_REPO} (labels/1/phishing_scams.csv, is_contract=True)`,
    license: "MIT (Forta Foundation), attributed in THIRD_PARTY_NOTICES.md",
    commit: commit.sha,
    as_of: commit.date,
    listed_contracts: listed.length,
    created_since: FORTA_SINCE,
    contracts_since: contracts.length,
    code_kinds: kinds,
    chains,
    fingerprints: blob.byteLength / 8,
  };
  writeFileSync(
    new URL("code-feeds.ts", DATA),
    [
      "// GENERATED by scripts/update-threat-feeds.ts --forta — do not edit by hand.",
      "// Logic-code fingerprints of Forta-labelled phishing contracts, as sorted SHA-256 prefixes in forta-drainer-code.bin.",
      `export const FORTA_CODE_META = ${JSON.stringify(meta)} as const;`,
      "",
    ].join("\n"),
  );
  console.log(`Forta ${commit.date} (${commit.sha.slice(0, 7)}): ${contracts.length} listed contracts → ${meta.fingerprints} logic fingerprints ${JSON.stringify(kinds)}`);
}

async function scamsniffer(upload: boolean): Promise<void> {
  const commit = await headCommit(SS_REPO);
  const [domains, addresses] = await Promise.all([getJson<string[]>(SS_LIST(commit.sha, "domains.json")), getJson<string[]>(SS_LIST(commit.sha, "address.json"))]);
  const hosts = domains.body.map(normalizeFeedDomain).filter((h): h is string => h !== null);
  const listed = addresses.body.map((a) => String(a).trim()).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase());
  // Never flagged, and never fingerprinted: a listed token contract would match every contract sharing its logic.
  const evm = listed.filter((a) => !neverFlag(a));
  if (evm.length < listed.length) console.log(`  left out ${listed.length - evm.length} never-flag address(es) (src/never-flag.ts)`);
  mkdirSync(CACHE, { recursive: true });
  const dBlob = buildHashBlob(hosts);
  const aBlob = buildHashBlob(evm);
  writeFileSync(new URL("scamsniffer-domains.bin", CACHE), dBlob);
  writeFileSync(new URL("scamsniffer-addresses.bin", CACHE), aBlob);
  const evmNetworks = Object.keys(BULK_RPC);
  const code = await codeFingerprints(evm, evmNetworks);
  const cBlob = buildHashBlob(code.fingerprints);
  writeFileSync(new URL("scamsniffer-code.bin", CACHE), cBlob);
  const meta = {
    source: `https://github.com/${SS_REPO}`,
    license: "GPL-3.0 (runtime use only; not distributed)",
    commit: commit.sha,
    as_of: commit.date,
    code_as_of: commit.date,
    refreshed_at: new Date().toISOString(),
    domains: dBlob.byteLength / 8,
    addresses: aBlob.byteLength / 8,
    code_fingerprints: cBlob.byteLength / 8,
    code_kinds: code.kinds,
    code_chains: code.chains,
    note: "public data is published with a 7-day delay",
  };
  writeFileSync(new URL("scamsniffer-meta.json", CACHE), JSON.stringify(meta));
  console.log(`ScamSniffer ${commit.date} (${commit.sha.slice(0, 7)}): ${meta.domains} hosts, ${meta.addresses} EVM addresses, ${meta.code_fingerprints} code fingerprints → ${fileURLToPath(CACHE)}`);
  if (!upload) return;
  const put = (key: string, file: URL): void => {
    // fileURLToPath, not URL.pathname: the latter keeps %20 for spaces in the checkout path.
    execFileSync("npx", ["wrangler", "kv", "key", "put", key, "--path", fileURLToPath(file), "--binding", "RATE", "--remote", "--config", "deploy/wrangler.toml"], { stdio: "inherit" });
  };
  put(KV_KEYS.domains, new URL("scamsniffer-domains.bin", CACHE));
  put(KV_KEYS.addresses, new URL("scamsniffer-addresses.bin", CACHE));
  put(KV_KEYS.code, new URL("scamsniffer-code.bin", CACHE));
  put(KV_KEYS.meta, new URL("scamsniffer-meta.json", CACHE));
  console.log("uploaded ScamSniffer blobs to KV (binding RATE)");
}

async function main(): Promise<void> {
  if (process.argv.includes("--forta")) await forta();
  await metamask();
  if (process.argv.includes("--scamsniffer")) await scamsniffer(process.argv.includes("--upload"));
}

// Importable (the kit hunter reuses the guarded set): only runs as a script.
if (process.argv[1]?.endsWith("update-threat-feeds.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

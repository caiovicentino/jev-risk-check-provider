// The cron's ScamSniffer refresh (audit prod-5): the stream parser, byte-for-byte equality with
// the manual build, the shrink guard and the separate date of the code set. Supply chain (security
// review F7): both lists read at the commit resolved first, the growth guard, the never-flag
// addresses, and feed entries that are not bare hosts. Synthetic data only (the real lists are GPL
// and never enter the repository).
import { test } from "node:test";
import assert from "node:assert";
import { jsonStrings, refreshScamSniffer, SCAMSNIFFER_KEYS } from "../deploy/scamsniffer-refresh.js";
import { buildHashBlob, hashSetFromBytes, normalizeFeedDomain } from "../src/threat-intel.js";
import { redactScamSniffer, scamSnifferOnly } from "../eval/redact.js";
import type { KVNamespace, WorkerEnv } from "../deploy/runtime.js";

/** A byte stream of `text` cut into chunks of `size` bytes (cuts land inside strings and escapes). */
function stream(text: string, size: number): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  let i = 0;
  return new ReadableStream({
    pull(controller) {
      if (i >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(i, i + size));
      i += size;
    },
  });
}

async function collect(gen: AsyncGenerator<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const s of gen) out.push(s);
  return out;
}

test("jsonStrings reads every string across chunk cuts, escapes and multi-byte characters", async () => {
  const values = ["a.example", 'quo"te.example', "back\\slash.example", "café.example", "\u{1F600}.example", ""];
  const text = `[\n  ${values.map((v) => JSON.stringify(v)).join(",\n  ")}\n]`;
  for (const size of [1, 2, 3, 7, 64, 4096]) assert.deepEqual(await collect(jsonStrings(stream(text, size))), values, `chunk size ${size}`);
  await assert.rejects(collect(jsonStrings(stream('["unterminated', 4))), /unterminated/);
  await assert.rejects(collect(jsonStrings(stream(JSON.stringify(["x".repeat(100)]), 8), 50)), /larger than/);
});

function memoryKv(): KVNamespace & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    get: (async (key: string) => (data.has(key) ? data.get(key) : null)) as KVNamespace["get"],
    put: async (key: string, value: unknown) => void data.set(key, value),
  };
}

const DOMAINS = Array.from({ length: 1500 }, (_, i) => (i % 3 === 0 ? `WWW.Scam-${i}.test` : `scam-${i}.test`)).concat(["https://has/path", "not a host", "scam-1.test"]);
const ADDRESSES = ["0x" + "Ab".repeat(20), "0x" + "cd".repeat(20), "bc1qnotevm", "0x123"];
const SHA = "f".repeat(40);
const LISTS = "https://raw.githubusercontent.com/scamsniffer/scam-database";
const NOW = new Date("2026-09-30T05:37:00Z");

/** The upstream, as served at any ref; `calls` records each URL in order. `commit`: false for a failed lookup, or the SHA the API returns. */
function fakeFetch(opts: { commit?: false | string; domains?: string[]; addresses?: string[] } = {}): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const impl = (async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/domains.json")) return new Response(stream(JSON.stringify(opts.domains ?? DOMAINS), 997));
    if (url.endsWith("/address.json")) return new Response(JSON.stringify(opts.addresses ?? ADDRESSES));
    if (new URL(url).hostname === "api.github.com") return opts.commit === false ? new Response("rate limited", { status: 403 }) : Response.json({ sha: opts.commit ?? SHA, commit: { committer: { date: "2026-09-29T12:00:00Z" } } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return Object.assign(impl, { calls });
}

test("the refresh writes the same bytes as the manual build and keeps the code set's own date", async () => {
  const kv = memoryKv();
  kv.data.set(SCAMSNIFFER_KEYS.meta, JSON.stringify({ as_of: "2026-09-01", code_fingerprints: 42, domains: 1200, addresses: 2 }));
  const env: WorkerEnv = { RATE: kv };
  const upstream = fakeFetch();
  const result = await refreshScamSniffer(env, upstream, NOW);
  assert.deepEqual(result, { status: "updated", domains: 1500, addresses: 2, never_flag_dropped: 0 });
  const hosts = DOMAINS.map(normalizeFeedDomain).filter((h): h is string => h !== null);
  assert.deepEqual(kv.data.get(SCAMSNIFFER_KEYS.domains), buildHashBlob(hosts));
  assert.deepEqual(kv.data.get(SCAMSNIFFER_KEYS.addresses), buildHashBlob(["0x" + "ab".repeat(20), "0x" + "cd".repeat(20)]));
  const meta = JSON.parse(kv.data.get(SCAMSNIFFER_KEYS.meta) as string) as Record<string, unknown>;
  assert.equal(meta.as_of, "2026-09-29");
  assert.equal(meta.as_of_source, "commit");
  assert.equal(meta.code_as_of, "2026-09-01", "the code set was built on its own date");
  assert.equal(meta.code_fingerprints, 42);
  assert.equal(meta.refreshed_at, "2026-09-30T05:37:00.000Z");
  // The commit is resolved first and both lists are read at it: the recorded SHA is the data's.
  assert.match(upstream.calls[0] ?? "", /^https:\/\/api\.github\.com\/repos\/scamsniffer\/scam-database\/commits\/main$/);
  assert.deepEqual(upstream.calls.slice(1), [`${LISTS}/${SHA}/blacklist/domains.json`, `${LISTS}/${SHA}/blacklist/address.json`]);
  assert.equal(meta.commit, SHA);
});

test("a list that shrank by half is kept as it was; without a usable commit, main and the fetch date are used", async () => {
  const kv = memoryKv();
  const before = JSON.stringify({ as_of: "2026-09-28", domains: 5000, addresses: 2 });
  kv.data.set(SCAMSNIFFER_KEYS.meta, before);
  const shrunk = await refreshScamSniffer({ RATE: kv }, fakeFetch(), NOW);
  assert.equal(shrunk.status, "kept");
  assert.equal(kv.data.get(SCAMSNIFFER_KEYS.meta), before);
  assert.equal(kv.data.has(SCAMSNIFFER_KEYS.domains), false);

  // A failed lookup, or a "SHA" that is not one (it would become part of the list URLs).
  for (const commit of [false, "../../other/repo/main", SHA.toUpperCase()] as const) {
    const fresh = memoryKv();
    fresh.data.set(SCAMSNIFFER_KEYS.meta, JSON.stringify({ as_of: "2026-09-28", commit: "e".repeat(40), domains: 1400, addresses: 2 }));
    const upstream = fakeFetch({ commit });
    const ok = await refreshScamSniffer({ RATE: fresh }, upstream, new Date("2026-09-30T17:37:00Z"));
    assert.equal(ok.status, "updated", String(commit));
    assert.deepEqual(upstream.calls.slice(1), [`${LISTS}/main/blacklist/domains.json`, `${LISTS}/main/blacklist/address.json`]);
    const meta = JSON.parse(fresh.data.get(SCAMSNIFFER_KEYS.meta) as string) as Record<string, unknown>;
    assert.deepEqual([meta.as_of, meta.as_of_source], ["2026-09-30", "fetched"]);
    assert.equal("commit" in meta, false, "the previous refresh's SHA does not describe this data");
    assert.equal("code_as_of" in meta, false, "no code set yet");
  }
});

test("a list that grew past either bound in one refresh is kept as it was: +50%, or +100,000 domains / +2,000 addresses", async () => {
  const kv = memoryKv();
  const before = JSON.stringify({ as_of: "2026-09-28", domains: 900, addresses: 2 });
  kv.data.set(SCAMSNIFFER_KEYS.meta, before);
  assert.deepEqual(await refreshScamSniffer({ RATE: kv }, fakeFetch(), NOW), { status: "kept", reason: "domains grew from 900 to 1500" });
  assert.equal(kv.data.get(SCAMSNIFFER_KEYS.meta), before);
  assert.equal(kv.data.has(SCAMSNIFFER_KEYS.domains), false);

  // +2,001 addresses is past the absolute bound although under +50%; +1,900 passes.
  const synthetic = (n: number) => Array.from({ length: n }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`);
  const many = memoryKv();
  many.data.set(SCAMSNIFFER_KEYS.meta, JSON.stringify({ as_of: "2026-09-28", domains: 1500, addresses: 5000 }));
  assert.deepEqual(await refreshScamSniffer({ RATE: many }, fakeFetch({ addresses: synthetic(7001) }), NOW), { status: "kept", reason: "addresses grew from 5000 to 7001" });
  assert.deepEqual(await refreshScamSniffer({ RATE: many }, fakeFetch({ addresses: synthetic(6900) }), NOW), { status: "updated", domains: 1500, addresses: 6900, never_flag_dropped: 0 });
});

test("addresses that must never be flagged are left out: our pay_to, the deployment's PAY_TO_EVM, USDC, Permit2", async () => {
  const neverFlagged = [
    "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178", // x402check's pay_to
    "0x" + "1A".repeat(20), // this deployment's PAY_TO_EVM (synthetic)
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
    "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", // USDC on Avalanche (x402's default asset there)
    "0x000000000022D473030F116dDEE9F6B43aC78BA3", // Permit2
  ];
  const kv = memoryKv();
  const result = await refreshScamSniffer({ RATE: kv, PAY_TO_EVM: "0x" + "1a".repeat(20) }, fakeFetch({ addresses: [...ADDRESSES, ...neverFlagged] }), NOW);
  assert.deepEqual(result, { status: "updated", domains: 1500, addresses: 2, never_flag_dropped: neverFlagged.length });
  const set = hashSetFromBytes(kv.data.get(SCAMSNIFFER_KEYS.addresses) as Uint8Array);
  for (const a of neverFlagged) assert.equal(set.has(a.toLowerCase()), false, a);
  assert.equal(set.has("0x" + "ab".repeat(20)), true);
  assert.equal((JSON.parse(kv.data.get(SCAMSNIFFER_KEYS.meta) as string) as Record<string, unknown>).never_flag_dropped, neverFlagged.length);
});

test("a feed entry is a bare host or nothing: userinfo, a port, a path, a query or a fragment is refused, never reduced to its host", () => {
  for (const entry of ["x@coinbase.com", "user:pass@coinbase.com", "coinbase.com:443", "coinbase.com:", "coinbase.com?q=1", "coinbase.com#f", "coinbase.com/", "https://coinbase.com", "coin%62ase.com", "coinbase.com\\x", "[::1]", "not a host", "localhost", ""]) {
    assert.equal(normalizeFeedDomain(entry), null, entry);
  }
  assert.equal(normalizeFeedDomain(" WWW.Scam-1.TEST. "), "scam-1.test");
  assert.equal(normalizeFeedDomain("sub.scam.co.uk"), "sub.scam.co.uk");
  assert.equal(normalizeFeedDomain("mеtamask.io"), "xn--mtamask-7gg.io", "a homoglyph is kept, as punycode");
});

test("report redaction still hides the host of a wrapped ScamSniffer entry, which the feed set now drops", async () => {
  const files: Record<string, string> = {
    "address.json": JSON.stringify(["0x" + "ab".repeat(20)]),
    "domains.json": JSON.stringify(["wrapped-scam.test:8443", "x@other-scam.test", "plain-scam.test", "shared.test"]),
    "phishing_scams.csv": "banned_address,is_contract\n",
    "config.json": JSON.stringify({ blacklist: ["shared.test"] }),
  };
  const fetchImpl = (async (input: string | URL | Request) => {
    const name = Object.keys(files).find((f) => String(input).endsWith(`/${f}`));
    return name ? new Response(files[name]) : new Response("not found", { status: 404 });
  }) as typeof fetch;
  const r = await scamSnifferOnly(fetchImpl);
  assert.deepEqual([...r.domains].sort(), ["other-scam.test", "plain-scam.test", "wrapped-scam.test"]);
  assert.equal(normalizeFeedDomain("wrapped-scam.test:8443"), null, "the feed set drops it");
  const out = redactScamSniffer({ note: "seen on wrapped-scam.test and shared.test" }, r);
  assert.doesNotMatch(out.note, /wrapped-scam/);
  assert.match(out.note, /shared\.test/, "MetaMask-listed hosts stay readable");
});

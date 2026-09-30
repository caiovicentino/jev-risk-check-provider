// The cron's ScamSniffer refresh (audit prod-5): the stream parser, byte-for-byte equality with
// the manual build, the shrink guard and the separate date of the code set. Synthetic data only
// (the real lists are GPL and never enter the repository).
import { test } from "node:test";
import assert from "node:assert";
import { jsonStrings, refreshScamSniffer, SCAMSNIFFER_KEYS } from "../deploy/scamsniffer-refresh.js";
import { buildHashBlob, normalizeFeedDomain } from "../src/threat-intel.js";
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

function fakeFetch(opts: { commit?: boolean; domains?: string[] } = {}): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith("/domains.json")) return new Response(stream(JSON.stringify(opts.domains ?? DOMAINS), 997));
    if (url.endsWith("/address.json")) return new Response(JSON.stringify(ADDRESSES));
    if (url.includes("api.github.com")) return opts.commit === false ? new Response("rate limited", { status: 403 }) : Response.json({ sha: "f".repeat(40), commit: { committer: { date: "2026-09-29T12:00:00Z" } } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

test("the refresh writes the same bytes as the manual build and keeps the code set's own date", async () => {
  const kv = memoryKv();
  kv.data.set(SCAMSNIFFER_KEYS.meta, JSON.stringify({ as_of: "2026-09-01", code_fingerprints: 42, domains: 1200, addresses: 2 }));
  const env: WorkerEnv = { RATE: kv };
  const result = await refreshScamSniffer(env, fakeFetch(), new Date("2026-09-30T05:37:00Z"));
  assert.deepEqual(result, { status: "updated", domains: 1500, addresses: 2 });
  const hosts = DOMAINS.map(normalizeFeedDomain).filter((h): h is string => h !== null);
  assert.deepEqual(kv.data.get(SCAMSNIFFER_KEYS.domains), buildHashBlob(hosts));
  assert.deepEqual(kv.data.get(SCAMSNIFFER_KEYS.addresses), buildHashBlob(["0x" + "ab".repeat(20), "0x" + "cd".repeat(20)]));
  const meta = JSON.parse(kv.data.get(SCAMSNIFFER_KEYS.meta) as string) as Record<string, unknown>;
  assert.equal(meta.as_of, "2026-09-29");
  assert.equal(meta.as_of_source, "commit");
  assert.equal(meta.code_as_of, "2026-09-01", "the code set was built on its own date");
  assert.equal(meta.code_fingerprints, 42);
  assert.equal(meta.refreshed_at, "2026-09-30T05:37:00.000Z");
});

test("a list that shrank by half is kept as it was; without GitHub's commit date, the fetch date is used", async () => {
  const kv = memoryKv();
  const before = JSON.stringify({ as_of: "2026-09-28", domains: 5000, addresses: 2 });
  kv.data.set(SCAMSNIFFER_KEYS.meta, before);
  const shrunk = await refreshScamSniffer({ RATE: kv }, fakeFetch(), new Date("2026-09-30T05:37:00Z"));
  assert.equal(shrunk.status, "kept");
  assert.equal(kv.data.get(SCAMSNIFFER_KEYS.meta), before);
  assert.equal(kv.data.has(SCAMSNIFFER_KEYS.domains), false);

  const fresh = memoryKv();
  const ok = await refreshScamSniffer({ RATE: fresh }, fakeFetch({ commit: false }), new Date("2026-09-30T17:37:00Z"));
  assert.equal(ok.status, "updated");
  const meta = JSON.parse(fresh.data.get(SCAMSNIFFER_KEYS.meta) as string) as Record<string, unknown>;
  assert.deepEqual([meta.as_of, meta.as_of_source], ["2026-09-30", "fetched"]);
  assert.equal("code_as_of" in meta, false, "no code set yet");
});

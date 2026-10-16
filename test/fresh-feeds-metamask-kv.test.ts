// The MetaMask list for new isolates (provider 0.6.10): the last verified list kept in KV is
// re-verified and applied with one read, so a new isolate no longer checks domains against the
// list embedded at deploy until its own refresh finishes (deploy/fresh-feeds.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { awaitColdStart, freshFeeds, loadMetamaskFromKv, maybeRefreshFeeds, METAMASK_KV_KEY, OFAC_KV_KEY, refreshFeeds } from "../deploy/fresh-feeds.js";
import { EMBEDDED, hangingFetch, memoryKv, OFAC_NEXT, release, TEST_PUBLIC_KEY } from "./fixtures/feeds-release.js";

const bundle = (r: ReturnType<typeof release>, over: Partial<{ manifest: string; sig: string; bin: string; json: string }> = {}) => JSON.stringify({ manifest: r.manifest, sig: r.sig, bin: Buffer.from(r.bin).toString("base64"), json: r.mmJson, ...over });

test("a tampered, unsigned or malformed bundle in KV is refused; nothing is applied", async () => {
  const r = release();
  const kv = memoryKv();
  kv.data.set(METAMASK_KV_KEY, bundle(r, { json: r.mmJson.replace("allowlist", "allowList") }));
  await assert.rejects(loadMetamaskFromKv(kv, EMBEDDED, TEST_PUBLIC_KEY), /checksum mismatch/);
  kv.data.set(METAMASK_KV_KEY, bundle(r, { manifest: r.manifest.replace("2026-10-03", "2026-10-04") }));
  await assert.rejects(loadMetamaskFromKv(kv, EMBEDDED, TEST_PUBLIC_KEY), /signature invalid/);
  kv.data.set(METAMASK_KV_KEY, JSON.stringify({ manifest: r.manifest, sig: r.sig }));
  await assert.rejects(loadMetamaskFromKv(kv, EMBEDDED, TEST_PUBLIC_KEY), /malformed bundle/);
  assert.equal(await loadMetamaskFromKv(memoryKv(), EMBEDDED, TEST_PUBLIC_KEY), null, "an empty KV holds no list");
  assert.equal(freshFeeds().metamask, undefined);
});

test("a new isolate checks domains against the KV list after one read, without waiting for the network", async () => {
  const r = release();
  const kv = memoryKv();
  kv.data.set(OFAC_KV_KEY, JSON.stringify({ manifest: r.manifest, sig: r.sig, ofac: r.ofacJson }));
  kv.data.set(METAMASK_KV_KEY, bundle(r));
  maybeRefreshFeeds({ FEEDS_URL: "https://feeds.example/", RATE: kv } as never, { waitUntil: () => undefined } as never, EMBEDDED, { fetchImpl: hangingFetch, publicKey: TEST_PUBLIC_KEY });
  const t = Date.now();
  await awaitColdStart();
  assert.ok(Date.now() - t < 1000, `waited ${Date.now() - t} ms`);
  const mm = freshFeeds().metamask;
  assert.deepEqual([mm?.as_of, mm?.entries, mm?.origin, mm?.set.has("phish-7.example"), mm?.set.has("example.com")], ["2026-01-02", 200, "kv", true, false]);
  const warm = Date.now();
  await awaitColdStart();
  assert.ok(Date.now() - warm < 20, "a warm isolate never waits");
});

test("the network refresh keeps a newer list in KV once, readable as published, and never over a newer one", async () => {
  const r = release(OFAC_NEXT, "2026-01-03");
  const kv = memoryKv();
  await refreshFeeds("https://feeds.example/", EMBEDDED, r.fetchImpl, TEST_PUBLIC_KEY, { kv, kvDate: async () => OFAC_NEXT, metamaskKvDate: async () => "2026-01-02" });
  assert.deepEqual(kv.puts, [METAMASK_KV_KEY]);
  assert.deepEqual([freshFeeds().metamask?.as_of, freshFeeds().metamask?.origin], ["2026-01-03", "network"]);
  // The bundle holds the published bytes: the manifest's checksums match what a new isolate decodes.
  const kept = JSON.parse(kv.data.get(METAMASK_KV_KEY) as string) as { manifest: string; sig: string; bin: string; json: string };
  const m = JSON.parse(kept.manifest) as { metamask: { bin_sha256: string; json_sha256: string } };
  assert.equal(kept.sig, r.sig);
  assert.equal(createHash("sha256").update(Buffer.from(kept.bin, "base64")).digest("hex"), m.metamask.bin_sha256);
  assert.equal(createHash("sha256").update(kept.json).digest("hex"), m.metamask.json_sha256);
  // KV holds this list or a newer one: no write.
  for (const held of ["2026-01-03", "2099-01-01"]) {
    const again = release(OFAC_NEXT, "2026-01-04");
    const before = kv.puts.length;
    await refreshFeeds("https://feeds.example/", EMBEDDED, again.fetchImpl, TEST_PUBLIC_KEY, { kv, kvDate: async () => OFAC_NEXT, metamaskKvDate: async () => (held === "2026-01-03" ? "2026-01-04" : held) });
    assert.equal(kv.puts.length, before, `held ${held}`);
  }
});

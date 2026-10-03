// OFAC for new isolates: the last verified release kept in KV is re-verified and applied with one
// read, written once per release and only forward, and a paid request on such an isolate does not
// wait for the network (deploy/fresh-feeds.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { awaitColdStart, loadOfacFromKv, maybeRefreshFeeds, OFAC_KV_KEY, refreshFeeds } from "../deploy/fresh-feeds.js";
import { sanctionsListMeta, screenSubject } from "../src/sanctions.js";
import { parseSubject } from "../src/address.js";
import { EMBEDDED, hangingFetch, memoryKv, NEW_SANCTIONED, OFAC_NEXT, release, TEST_PUBLIC_KEY } from "./fixtures/feeds-release.js";

const subject = parseSubject(NEW_SANCTIONED)!;

test("a tampered or unsigned bundle in KV is refused; nothing is applied", async () => {
  const r = release();
  const kv = memoryKv();
  kv.data.set(OFAC_KV_KEY, JSON.stringify({ manifest: r.manifest, sig: r.sig, ofac: r.ofacJson.replace("TEST ENTITY", "OTHER ENTITY") }));
  await assert.rejects(loadOfacFromKv(kv, EMBEDDED, TEST_PUBLIC_KEY), /checksum mismatch/);
  kv.data.set(OFAC_KV_KEY, JSON.stringify({ manifest: r.manifest.replace("2026-10-03", "2026-10-04"), sig: r.sig, ofac: r.ofacJson }));
  await assert.rejects(loadOfacFromKv(kv, EMBEDDED, TEST_PUBLIC_KEY), /signature invalid/);
  assert.equal(await loadOfacFromKv(memoryKv(), EMBEDDED, TEST_PUBLIC_KEY), null, "an empty KV holds no release");
  assert.equal(screenSubject(subject).status, "not_listed");
});

test("a new isolate applies the KV release with one read, and a paid request does not wait for the network", async () => {
  const r = release();
  const kv = memoryKv();
  kv.data.set(OFAC_KV_KEY, JSON.stringify({ manifest: r.manifest, sig: r.sig, ofac: r.ofacJson }));
  maybeRefreshFeeds({ FEEDS_URL: "https://feeds.example/", RATE: kv } as never, { waitUntil: () => undefined } as never, EMBEDDED, { fetchImpl: hangingFetch, publicKey: TEST_PUBLIC_KEY });
  const t = Date.now();
  await awaitColdStart();
  assert.ok(Date.now() - t < 1000, `waited ${Date.now() - t} ms`);
  assert.equal(sanctionsListMeta().publish_date, OFAC_NEXT);
  assert.equal(screenSubject(subject).status, "listed");
  const warm = Date.now();
  await awaitColdStart();
  assert.ok(Date.now() - warm < 20, "a warm isolate never waits");
});

test("the network refresh writes a release to KV once, and never over a newer one", async () => {
  // The list in use is OFAC_NEXT now: a publish one day later is newer still.
  const later = new Date(Date.parse(`${OFAC_NEXT}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
  const r = release(later);
  const kv = memoryKv();
  let ofacSteps = 0;
  await refreshFeeds("https://feeds.example/", EMBEDDED, r.fetchImpl, TEST_PUBLIC_KEY, { kv, kvDate: async () => OFAC_NEXT, onOfac: () => ofacSteps++ });
  assert.deepEqual(kv.puts, [OFAC_KV_KEY]);
  assert.equal(ofacSteps, 1);
  assert.equal(sanctionsListMeta().publish_date, later);
  assert.ok(r.fetched.indexOf("ofac-sdn.json") < r.fetched.indexOf("metamask-phishing.bin"), "OFAC is fetched before MetaMask");
  // KV holds this release, or a newer one: no write, and no OFAC download either.
  for (const held of [later, "2099-01-01"]) {
    const again = release(later);
    await refreshFeeds("https://feeds.example/", EMBEDDED, again.fetchImpl, TEST_PUBLIC_KEY, { kv, kvDate: async () => held });
    assert.deepEqual(kv.puts, [OFAC_KV_KEY], `held ${held}`);
    assert.ok(!again.fetched.includes("ofac-sdn.json"));
  }
});

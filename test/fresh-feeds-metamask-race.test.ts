// A new isolate loads the MetaMask list from KV while its network refresh runs: the refresh must
// never take that list back (reported by the 2026-10-16 review: the refresh wrote back a copy of
// the state taken before its downloads, and the isolate fell back to the list embedded at deploy).
import { test } from "node:test";
import assert from "node:assert/strict";
import { freshFeeds, maybeRefreshFeeds, METAMASK_KV_KEY, OFAC_KV_KEY } from "../deploy/fresh-feeds.js";
import { EMBEDDED, release, TEST_PUBLIC_KEY } from "./fixtures/feeds-release.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("the KV list survives a refresh that finishes after it, and a stale manifest never takes back a newer list", async () => {
  // KV holds the 2026-01-03 list; the network (a stale CDN copy) still serves the 2026-01-02 manifest.
  const kvRelease = release(undefined, "2026-01-03");
  const netRelease = release();
  const data = new Map<string, string>([
    [OFAC_KV_KEY, JSON.stringify({ manifest: netRelease.manifest, sig: netRelease.sig, ofac: netRelease.ofacJson })],
    [METAMASK_KV_KEY, JSON.stringify({ manifest: kvRelease.manifest, sig: kvRelease.sig, bin: Buffer.from(kvRelease.bin).toString("base64"), json: kvRelease.mmJson })],
  ]);
  // The manifest comes first (edge cache), KV reads take longer, and the OFAC snapshot download is slowest:
  // the KV list lands in the middle of the refresh.
  const kv = { get: async (key: string) => (await sleep(key === OFAC_KV_KEY ? 50 : 100), data.get(key) ?? null), put: async (key: string, value: string) => void data.set(key, value) };
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    await sleep(new URL(url).pathname.endsWith("ofac-sdn.json") ? 150 : 5);
    return netRelease.fetchImpl(url, init);
  }) as unknown as typeof fetch;
  const waits: Promise<unknown>[] = [];
  const seen: string[] = [];
  const poll = setInterval(() => {
    const mm = freshFeeds().metamask;
    const now = mm ? `${mm.as_of}/${mm.origin}` : "embedded";
    if (seen[seen.length - 1] !== now) seen.push(now);
  }, 1);
  await maybeRefreshFeeds({ FEEDS_URL: "https://feeds.example/", RATE: kv } as never, { waitUntil: (p: Promise<unknown>) => void waits.push(p) } as never, EMBEDDED, { fetchImpl, publicKey: TEST_PUBLIC_KEY });
  await Promise.allSettled(waits);
  await sleep(10);
  clearInterval(poll);
  assert.deepEqual(seen, ["embedded", "2026-01-03/kv"], "applied once from KV, never taken back");
  assert.equal(freshFeeds().checked_at !== undefined, true, "the refresh itself completed");
});

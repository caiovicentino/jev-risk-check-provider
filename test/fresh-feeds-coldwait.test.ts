// A cold isolate with no KV release and a network that hangs: the first paid request waits about
// 2.5 s for a current OFAC list, then proceeds on the list it has and says so once; the isolate
// never waits again (deploy/fresh-feeds.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { awaitColdStart, maybeRefreshFeeds } from "../deploy/fresh-feeds.js";
import { sanctionsListMeta } from "../src/sanctions.js";
import { OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { EMBEDDED, hangingFetch, memoryKv, TEST_PUBLIC_KEY } from "./fixtures/feeds-release.js";

test("the first paid request waits at most ~2.5 s, then the isolate stops waiting", async () => {
  const warnings: string[] = [];
  const warn = console.warn;
  console.warn = (msg: string) => void warnings.push(String(msg));
  try {
    maybeRefreshFeeds({ FEEDS_URL: "https://feeds.example/", RATE: memoryKv() } as never, { waitUntil: () => undefined } as never, EMBEDDED, { fetchImpl: hangingFetch, publicKey: TEST_PUBLIC_KEY });
    const t = Date.now();
    await awaitColdStart();
    const waited = Date.now() - t;
    assert.ok(waited >= 2400 && waited < 4000, `waited ${waited} ms`);
    assert.equal(sanctionsListMeta().publish_date, OFAC_SDN_META.publish_date, "the embedded list, with its own date");
    const again = Date.now();
    await awaitColdStart();
    assert.ok(Date.now() - again < 20, "no second wait");
    assert.equal(warnings.filter((w) => w.includes("went ahead on the")).length, 1, "said once");
  } finally {
    console.warn = warn;
  }
});

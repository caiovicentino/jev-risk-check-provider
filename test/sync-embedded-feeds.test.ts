// The embedded OFAC snapshot is synced from the published feeds release (scripts/sync-embedded-feeds.ts),
// verified as the Worker verifies it at runtime, and scripts/deploy.sh refuses a stale one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { embeddedStatus, publishedOfacDate, verifyPublishedOfac } from "../scripts/sync-embedded-feeds.js";
import { renderOfacModule } from "../scripts/update-ofac.js";
import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "../src/data/ofac-sdn.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUBLIC = (publicKey.export({ format: "jwk" }) as { x: string }).x;
const enc = (s: string) => new TextEncoder().encode(s);

/** A published release as scripts/publish-feeds.ts writes it, signed with the test key. */
function release(rows: Array<[string, string, number, string]>, patch: { manifestOfac?: Record<string, unknown>; meta?: Record<string, unknown> } = {}) {
  const meta = { source: "OFAC SDN", publish_date: "2026-10-02", record_count: 19488, addresses: rows.length, by_ticker: { ETH: rows.length }, sha256: "a".repeat(64), ...patch.meta };
  const ofacJson = JSON.stringify({ meta, rows });
  const manifest = enc(JSON.stringify({ format: 1, generated_at: "2026-10-03T11:00:00.000Z", ofac: { publish_date: "2026-10-02", addresses: rows.length, json_sha256: createHash("sha256").update(ofacJson).digest("hex"), xml_sha256: "a".repeat(64), ...patch.manifestOfac } }));
  return { manifest, sig: sign(null, manifest, privateKey).toString("base64url"), ofac: enc(ofacJson) };
}
const ROWS: Array<[string, string, number, string]> = [["0x1111111111111111111111111111111111111111", "ETH", 1, "A"], ["0x2222222222222222222222222222222222222222", "ETH", 2, "B"]];

test("embedded vs published: older is stale, the same date is current", () => {
  assert.equal(embeddedStatus("2026-09-29", "2026-10-02"), "stale");
  assert.equal(embeddedStatus("2026-10-02", "2026-10-02"), "current");
  assert.equal(embeddedStatus("2026-10-03", "2026-10-02"), "ahead");
});

test("a published release is used only when the signature, checksum, count, date and digest all agree", async () => {
  const r = release(ROWS);
  assert.equal(await publishedOfacDate(r.manifest, r.sig, PUBLIC), "2026-10-02");
  const ok = await verifyPublishedOfac(r.manifest, r.sig, r.ofac, PUBLIC);
  assert.deepEqual(ok.rows, ROWS);
  assert.equal(ok.meta.publish_date, "2026-10-02");
  await assert.rejects(verifyPublishedOfac(r.manifest, r.sig.slice(0, -2) + "AA", r.ofac, PUBLIC), /signature invalid/);
  await assert.rejects(verifyPublishedOfac(r.manifest, r.sig, enc(new TextDecoder().decode(r.ofac).replace("0x1111", "0x9111")), PUBLIC), /checksum mismatch/);
  const miscounted = release(ROWS, { manifestOfac: { addresses: 3 } });
  await assert.rejects(verifyPublishedOfac(miscounted.manifest, miscounted.sig, miscounted.ofac, PUBLIC), /count that disagrees/);
  const digest = release(ROWS, { meta: { sha256: "b".repeat(64) } });
  await assert.rejects(verifyPublishedOfac(digest.manifest, digest.sig, digest.ofac, PUBLIC), /SDN\.XML digest disagrees/);
  const dated = release(ROWS, { meta: { publish_date: "2026-10-01" } });
  await assert.rejects(verifyPublishedOfac(dated.manifest, dated.sig, dated.ofac, PUBLIC), /meta disagrees/);
});

test("the module the sync writes is the one update-ofac.ts writes", () => {
  const rendered = renderOfacModule(OFAC_SDN_META as never, OFAC_SDN_ADDRESSES as never);
  assert.equal(rendered, readFileSync(new URL("../src/data/ofac-sdn.ts", import.meta.url), "utf8"));
});

test("deploy.sh checks the embedded snapshot after installing and before deploying", () => {
  const script = readFileSync(new URL("../scripts/deploy.sh", import.meta.url), "utf8");
  const install = script.indexOf("npm ci --ignore-scripts");
  const check = script.indexOf("scripts/sync-embedded-feeds.ts --check");
  const deploy = script.indexOf('"${wrangler[@]}" deploy');
  assert.ok(install > 0 && check > install && deploy > check, "install, then the check, then wrangler deploy");
});

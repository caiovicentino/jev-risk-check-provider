import { test } from "node:test";
import assert from "node:assert";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { refreshFeeds, freshFeeds } from "../deploy/fresh-feeds.js";
import { buildHashBlob } from "../src/threat-intel.js";
import { sanctionsListMeta, screenSubject, setSanctionsList } from "../src/sanctions.js";
import { parseSubject } from "../src/address.js";
import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "../src/data/ofac-sdn.js";

const BASE = "https://feeds.example/";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUB = publicKey.export({ format: "jwk" }).x as string;
const sha = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const NEW_SANCTIONED = "0x9999999999999999999999999999999999999999";

function published(opts: { mmAsOf?: string; mmHosts?: string[]; ofacDate?: string; ofacRows?: ReadonlyArray<readonly [string, string, number, string]>; corrupt?: "bin" | "ofac"; badSig?: boolean; allowlist?: string[]; snapshotSha?: string; manifestSha?: string } = {}) {
  const bin = buildHashBlob(opts.mmHosts ?? Array.from({ length: 200 }, (_, i) => `phish-${i}.example`));
  const mmJson = JSON.stringify({ meta: { as_of: opts.mmAsOf ?? "2026-01-02" }, allowlist: opts.allowlist ?? ["opensea.pro"] });
  const rows = opts.ofacRows ?? [...OFAC_SDN_ADDRESSES, [NEW_SANCTIONED, "ETH", 1, "TEST ENTITY"] as const];
  const ofacJson = JSON.stringify({ meta: { source: "test", ...(opts.snapshotSha ? { sha256: opts.snapshotSha } : {}) }, rows });
  const manifest = {
    format: 1,
    generated_at: "2099-01-01T00:00:00Z",
    metamask: { as_of: opts.mmAsOf ?? "2026-01-02", entries: bin.byteLength / 8, bin_sha256: sha(bin), json_sha256: sha(mmJson) },
    ofac: { publish_date: opts.ofacDate ?? OFAC_NEXT, addresses: rows.length, json_sha256: opts.corrupt === "ofac" ? "0".repeat(64) : sha(ofacJson), ...(opts.manifestSha ? { xml_sha256: opts.manifestSha } : {}) },
  };
  const manifestText = JSON.stringify(manifest);
  const signature = sign(null, Buffer.from(opts.badSig ? `${manifestText} ` : manifestText), privateKey).toString("base64url");
  const files: Record<string, Uint8Array | string> = {
    "manifest.json": manifestText,
    "manifest.sig": signature,
    "metamask-phishing.bin": opts.corrupt === "bin" ? bin.slice(8) : bin,
    "metamask.json": mmJson,
    "ofac-sdn.json": ofacJson,
  };
  return (async (url: string) => {
    const name = new URL(url).pathname.slice(1); // the hourly ?h= cache key is ignored
    const body = files[name];
    return body === undefined ? new Response("nope", { status: 404 }) : new Response(typeof body === "string" ? body : new Uint8Array(body));
  }) as unknown as typeof fetch;
}

const embedded = { metamaskAsOf: "2026-01-01", metamaskEntries: 150, ofacRows: OFAC_SDN_META.addresses };
// A publication one day newer than the embedded OFAC snapshot (whatever `npm run ofac:update` produced).
const OFAC_NEXT = new Date(Date.parse(`${OFAC_SDN_META.publish_date}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
const refresh = (fetchImpl: typeof fetch, base = embedded) => refreshFeeds(BASE, base, fetchImpl, PUB);

test("a corrupted MetaMask blob is rejected; the embedded list stays in use", async () => {
  await assert.rejects(refresh(published({ corrupt: "bin", ofacDate: "2000-01-01" })), /metamask: checksum mismatch/);
  assert.equal(freshFeeds().metamask, undefined);
  assert.match(freshFeeds().error ?? "", /checksum/);
});

test("a large shrink is rejected (truncated or emptied list)", async () => {
  await assert.rejects(refresh(published({ ofacDate: "2000-01-01" }), { ...embedded, metamaskEntries: 10_000 }), /large shrink/);
  assert.equal(freshFeeds().metamask, undefined);
});

test("a newer, verified MetaMask list is swapped in; an older one is ignored", async () => {
  const state = await refresh(published({ ofacDate: "2000-01-01" }));
  assert.equal(state.metamask?.as_of, "2026-01-02");
  assert.ok(state.metamask?.set.has("phish-7.example"));
  assert.ok(state.metamask?.allow.has("opensea.pro"));
  const again = await refresh(published({ mmAsOf: "2026-01-01", mmHosts: ["other.example"], ofacDate: "2000-01-01" }));
  assert.equal(again.metamask?.as_of, "2026-01-02", "never goes back to an older list");
});

test("OFAC: a corrupted snapshot is rejected; a newer verified one is screened immediately", async () => {
  const subject = parseSubject(NEW_SANCTIONED);
  assert.ok(subject);
  assert.equal(screenSubject(subject).status, "not_listed");
  await assert.rejects(refresh(published({ corrupt: "ofac" })), /ofac: checksum mismatch/);
  assert.equal(sanctionsListMeta().origin, "embedded");
  await assert.rejects(refresh(published({ ofacRows: OFAC_SDN_ADDRESSES.slice(0, 10) })), /large shrink/);
  await refresh(published());
  const r = screenSubject(subject);
  assert.equal(r.status, "listed");
  assert.equal(r.as_of, OFAC_NEXT);
  assert.equal(sanctionsListMeta().origin, "refreshed");
});

test("an unsigned, wrongly signed or future-dated publish is rejected", async () => {
  await assert.rejects(refresh(published({ badSig: true })), /signature invalid/);
  await assert.rejects(refreshFeeds(BASE, embedded, published(), generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x as string), /signature invalid/, "a different publisher key");
  await assert.rejects(refresh(published({ mmAsOf: "9999-12-31", ofacDate: "2000-01-01" })), /implausible date/);
  await assert.rejects(refresh(published({ mmAsOf: "2026-02-01", ofacDate: "2000-01-01", allowlist: Array.from({ length: 600 }, (_, i) => `allowed${i}.example`) })), /implausible/);
});

test("OFAC: a refreshed list carries its SDN.XML digest; a disagreeing digest is refused; none is never invented", async () => {
  const subject = parseSubject(NEW_SANCTIONED);
  assert.ok(subject);
  // Each step starts from an older list, so the same publication (OFAC_NEXT) is newer every time.
  const rewind = () => setSanctionsList(OFAC_SDN_ADDRESSES, { source: "test", publish_date: "2000-01-01" });
  const hex = "cd".repeat(32);
  rewind();
  await refresh(published({ snapshotSha: hex, manifestSha: hex }));
  assert.equal(sanctionsListMeta().digest, `sha256:${hex}`);
  assert.equal(screenSubject(subject).digest, `sha256:${hex}`);

  rewind();
  await assert.rejects(refresh(published({ snapshotSha: hex, manifestSha: "ef".repeat(32) })), /source digest mismatch/);
  assert.equal(sanctionsListMeta().publish_date, "2000-01-01", "the disagreeing snapshot was not swapped in");

  rewind();
  await refresh(published({ snapshotSha: "not-a-digest" }));
  assert.equal(sanctionsListMeta().publish_date, OFAC_NEXT);
  assert.equal(sanctionsListMeta().digest, undefined, "an unusable digest is omitted, never borrowed from another list");
  assert.equal(screenSubject(subject).digest, undefined);
});

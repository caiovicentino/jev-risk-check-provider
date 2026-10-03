// Syncs the OFAC snapshot embedded in the Worker (src/data/ofac-sdn.ts) with the release the
// `feeds` branch publishes (scripts/publish-feeds.ts), verified exactly as the Worker verifies it
// at runtime: the Ed25519 signature over the manifest (pinned publisher key), the SHA-256 of
// ofac-sdn.json, its entry count and the SDN.XML digest. Until its first refresh lands, a new
// isolate screens against the embedded list, so a release syncs it first (AGENTS.md §3.3) and
// scripts/deploy.sh refuses to deploy an embedded snapshot older than the published release.
//
//   npx tsx scripts/sync-embedded-feeds.ts           # rewrite src/data/ofac-sdn.ts when the published release is newer
//   npx tsx scripts/sync-embedded-feeds.ts --check   # exit 1 when the embedded snapshot is older; 2 when it cannot tell
//
// The files are read through the GitHub API (the raw CDN can serve a stale copy); GH_TOKEN or
// GITHUB_TOKEN is used when set.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { FEEDS_PUBLIC_KEY, saneDate, verifyManifest } from "../deploy/fresh-feeds.js";
import { OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { OFAC_MODULE, renderOfacModule, type OfacMeta, type OfacRow } from "./update-ofac.js";

const REPO = "caiovicentino/jev-risk-check-provider";

/** The embedded snapshot against the published release (YYYY-MM-DD dates compare as strings). */
export function embeddedStatus(embedded: string, published: string): "current" | "stale" | "ahead" {
  return embedded === published ? "current" : embedded < published ? "stale" : "ahead";
}

type PublishedManifest = { ofac?: { publish_date?: unknown; addresses?: unknown; json_sha256?: unknown; xml_sha256?: unknown } };

/** The published manifest's OFAC release date, once its signature verifies. */
export async function publishedOfacDate(manifest: Uint8Array, signature: string, publicKey = FEEDS_PUBLIC_KEY): Promise<string> {
  if (!(await verifyManifest(manifest.slice().buffer, signature, publicKey))) throw new Error("manifest: signature invalid");
  const date = (JSON.parse(new TextDecoder().decode(manifest)) as PublishedManifest).ofac?.publish_date;
  if (!saneDate(date)) throw new Error("manifest: no plausible OFAC release date");
  return date;
}

/**
 * The published OFAC snapshot, verified against the signed manifest: signature, SHA-256 of the
 * file, row shape and count, release date and SDN.XML digest. Throws on any mismatch.
 */
export async function verifyPublishedOfac(manifest: Uint8Array, signature: string, ofacJson: Uint8Array, publicKey = FEEDS_PUBLIC_KEY): Promise<{ meta: OfacMeta; rows: OfacRow[] }> {
  const date = await publishedOfacDate(manifest, signature, publicKey);
  const of = (JSON.parse(new TextDecoder().decode(manifest)) as PublishedManifest).ofac ?? {};
  if (createHash("sha256").update(ofacJson).digest("hex") !== of.json_sha256) throw new Error("ofac-sdn.json: checksum mismatch");
  const parsed = JSON.parse(new TextDecoder().decode(ofacJson)) as { meta?: Partial<OfacMeta>; rows?: unknown };
  const rows = Array.isArray(parsed.rows) ? parsed.rows : [];
  const valid = rows.every((r): r is OfacRow => Array.isArray(r) && r.length === 4 && typeof r[0] === "string" && r[0].length > 0 && r[0].length <= 128 && typeof r[1] === "string" && typeof r[2] === "number" && typeof r[3] === "string");
  if (!valid || rows.length !== of.addresses) throw new Error("ofac-sdn.json: malformed rows or a count that disagrees with the manifest");
  const meta = parsed.meta;
  if (!meta || meta.publish_date !== date || meta.addresses !== rows.length) throw new Error("ofac-sdn.json: meta disagrees with the manifest");
  if (typeof of.xml_sha256 === "string" && meta.sha256 !== of.xml_sha256) throw new Error("ofac-sdn.json: SDN.XML digest disagrees with the manifest");
  if (typeof meta.source !== "string" || typeof meta.record_count !== "number" || typeof meta.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(meta.sha256) || !meta.by_ticker || typeof meta.by_ticker !== "object") throw new Error("ofac-sdn.json: incomplete meta");
  return { meta: meta as OfacMeta, rows: rows as OfacRow[] };
}

async function fetchFeed(name: string): Promise<Uint8Array> {
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  const res = await fetch(`https://api.github.com/repos/${REPO}/contents/${name}?ref=feeds`, {
    headers: { Accept: "application/vnd.github.raw", "User-Agent": "x402check-sync-embedded-feeds", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function main(): Promise<void> {
  const check = process.argv.includes("--check");
  let manifest: Uint8Array;
  let signature: string;
  let published: string;
  try {
    [manifest, signature] = await Promise.all([fetchFeed("manifest.json"), fetchFeed("manifest.sig").then((b) => new TextDecoder().decode(b))]);
    published = await publishedOfacDate(manifest, signature);
  } catch (err) {
    console.error(`sync-embedded-feeds: the published release could not be read or verified (${String(err instanceof Error ? err.message : err)})`);
    process.exit(2);
  }
  const embedded = OFAC_SDN_META.publish_date;
  const status = embeddedStatus(embedded, published);
  if (check) {
    if (status === "stale") {
      console.error(`sync-embedded-feeds: the embedded OFAC snapshot (${embedded}) is older than the published release (${published}): run npx tsx scripts/sync-embedded-feeds.ts and commit`);
      process.exit(1);
    }
    console.log(`sync-embedded-feeds: the embedded OFAC snapshot (${embedded}) is ${status === "current" ? "the published release" : `newer than the published release (${published})`}`);
    return;
  }
  if (status !== "stale") {
    console.log(`sync-embedded-feeds: nothing to do (embedded ${embedded}, published ${published})`);
    return;
  }
  const { meta, rows } = await verifyPublishedOfac(manifest, signature, await fetchFeed("ofac-sdn.json"));
  writeFileSync(OFAC_MODULE, renderOfacModule(meta, rows));
  console.log(`sync-embedded-feeds: src/data/ofac-sdn.ts ${embedded} → ${meta.publish_date} (${rows.length} addresses, SDN.XML sha256:${meta.sha256.slice(0, 12)}…)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

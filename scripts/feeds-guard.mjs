// The feeds workflow's last check before signing (security review F7a). The manifest the build
// job produced is compared with the one published on the `feeds` branch, and an implausible
// change is not signed. The build job runs dependency code; this script runs in the publish job
// with plain node (only node:* imports, nothing installed), checked out from the run's commit and
// never taken from the build artifact.
//
//   node scripts/feeds-guard.mjs <new manifest.json> <published manifest.json> [<new ofac-sdn.json> <published ofac-sdn.json>]
//
// With the two OFAC snapshots it also compares the address sets: OFAC rarely delists, so any
// address missing from the new snapshot is refused until a person reviews it (a count-only check
// would pass a tampered build that drops one sanctioned address and adds a junk one). Each
// snapshot must match its manifest's SHA-256, so the guard checks exactly what is signed.
// Only counts are ever printed, never an address.
//
// Exit 0: sign. Exit 1: refused, with the reasons; a missing or unreadable published manifest or
// snapshot is a refusal too. FEEDS_GUARD_OVERRIDE=1 (the workflow's manual `override` input, set
// by a person who reviewed the reasons) publishes anyway and prints them as warnings.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** The largest change one publish may carry (the workflow runs daily). */
export const LIMITS = Object.freeze({
  /** OFAC rarely delists; a larger drop looks like a broken or tampered build. */
  ofacMaxShrink: 0.05,
  ofacMaxGrowth: 0.5,
  /** MetaMask entries, either way. */
  metamaskMaxChange: 0.2,
  /** A date may run ahead of the runner's clock by at most this (time zones). */
  maxAheadMs: 24 * 60 * 60 * 1000,
});

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

// Strict formats first: only validated values are ever printed (the output is read as workflow commands).
const DATES = [
  ["generated_at", (m) => m?.generated_at, INSTANT],
  ["metamask.as_of", (m) => m?.metamask?.as_of, DAY],
  ["ofac.publish_date", (m) => m?.ofac?.publish_date, DAY],
];
const metamaskEntries = (m) => m?.metamask?.entries;
const ofacAddresses = (m) => m?.ofac?.addresses;
const COUNTS = [
  ["metamask.entries", metamaskEntries],
  ["ofac.addresses", ofacAddresses],
];

const time = (value, format) => (typeof value === "string" && format.test(value) ? Date.parse(format === DAY ? `${value}T00:00:00Z` : value) : NaN);
const isCount = (value) => Number.isSafeInteger(value) && value > 0;
const pct = (ratio) => `${(ratio * 100).toFixed(1)}%`;

/** The fields of a manifest that are missing or malformed. */
function invalid(manifest) {
  return [...DATES.filter(([, get, format]) => !Number.isFinite(time(get(manifest), format))), ...COUNTS.filter(([, get]) => !isCount(get(manifest)))].map(([field]) => field);
}

/**
 * The reasons not to sign `next` (the manifest the build produced) given `published` (the one on
 * the `feeds` branch, or null when there is none); an empty array means sign.
 */
export function feedsGuard(next, published, now = Date.now()) {
  const bad = invalid(next);
  if (bad.length) return [`new manifest: ${bad.join(", ")} missing or invalid`];
  const reasons = [];
  // A future date would also make every later, correct publish look like it went backwards.
  for (const [field, get, format] of DATES) if (time(get(next), format) > now + LIMITS.maxAheadMs) reasons.push(`${field} ${get(next)} is in the future`);
  if (!published) return [...reasons, "no published manifest to compare with"];
  const badPublished = invalid(published);
  if (badPublished.length) return [...reasons, `published manifest: ${badPublished.join(", ")} missing or invalid`];

  for (const [field, get, format] of DATES) if (time(get(next), format) < time(get(published), format)) reasons.push(`${field} went backwards: ${get(published)} → ${get(next)}`);
  const change = (get) => (get(next) - get(published)) / get(published);
  const span = (get) => `${get(published)} → ${get(next)}`;
  const ofac = change(ofacAddresses);
  if (ofac < -LIMITS.ofacMaxShrink) reasons.push(`OFAC addresses shrank by ${pct(-ofac)} (${span(ofacAddresses)}), more than ${pct(LIMITS.ofacMaxShrink)}`);
  if (ofac > LIMITS.ofacMaxGrowth) reasons.push(`OFAC addresses grew by ${pct(ofac)} (${span(ofacAddresses)}), more than ${pct(LIMITS.ofacMaxGrowth)}`);
  const mm = change(metamaskEntries);
  if (Math.abs(mm) > LIMITS.metamaskMaxChange) reasons.push(`MetaMask entries moved by ${pct(mm)} (${span(metamaskEntries)}), more than ${pct(LIMITS.metamaskMaxChange)}`);
  return reasons;
}

/** The addresses of an ofac-sdn.json snapshot (exact text), or null when it is not one. */
function snapshotAddresses(text) {
  try {
    const parsed = JSON.parse(text);
    if (!parsed || !Array.isArray(parsed.rows)) return null;
    const out = new Set();
    for (const r of parsed.rows) {
      if (!Array.isArray(r) || typeof r[0] !== "string" || r[0].length === 0) return null;
      out.add(r[0]);
    }
    return out;
  } catch {
    return null;
  }
}

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/**
 * The reasons not to sign given the OFAC snapshots (exact file text; null when unavailable):
 * each must match its manifest's SHA-256, and no published address may be missing from the new one.
 */
export function ofacSetGuard(nextManifest, publishedManifest, nextOfac, publishedOfac) {
  if (typeof nextOfac !== "string" || sha256(nextOfac) !== nextManifest?.ofac?.json_sha256) return ["new OFAC snapshot: missing, or not the one the manifest names"];
  const next = snapshotAddresses(nextOfac);
  if (!next) return ["new OFAC snapshot: malformed rows"];
  if (typeof publishedOfac !== "string") return ["no published OFAC snapshot to compare with"];
  if (sha256(publishedOfac) !== publishedManifest?.ofac?.json_sha256) return ["published OFAC snapshot: not the one the published manifest names"];
  const published = snapshotAddresses(publishedOfac);
  if (!published) return ["published OFAC snapshot: malformed rows"];
  let removed = 0;
  for (const a of published) if (!next.has(a)) removed++;
  return removed ? [`OFAC: ${removed} address(es) of the published list are missing from the new one (a delisting must be reviewed; publish it with override)`] : [];
}

function text(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function load(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [nextPath, publishedPath, nextOfacPath, publishedOfacPath] = process.argv.slice(2);
  if (!nextPath || !publishedPath || !nextOfacPath !== !publishedOfacPath) {
    console.error("usage: node scripts/feeds-guard.mjs <new manifest.json> <published manifest.json> [<new ofac-sdn.json> <published ofac-sdn.json>]");
    process.exit(2);
  }
  const next = load(nextPath);
  const published = load(publishedPath);
  const reasons = feedsGuard(next, published);
  if (nextOfacPath && publishedOfacPath && reasons.length === 0) reasons.push(...ofacSetGuard(next, published, text(nextOfacPath), text(publishedOfacPath)));
  if (reasons.length === 0) {
    console.log(`feeds guard: ok (MetaMask ${next.metamask.as_of}, ${next.metamask.entries} entries; OFAC ${next.ofac.publish_date}, ${next.ofac.addresses} addresses${nextOfacPath ? ", none delisted" : ""})`);
  } else if (process.env.FEEDS_GUARD_OVERRIDE === "1") {
    for (const r of reasons) console.log(`::warning title=feeds guard (overridden)::${r}`);
  } else {
    for (const r of reasons) console.log(`::error title=feeds guard::${r}`);
    console.log("Not signed. Review the change; to publish it anyway, run the workflow by hand with `override`.");
    process.exit(1);
  }
}

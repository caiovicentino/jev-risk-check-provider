// The feeds workflow's last check before signing (security review F7a). The manifest the build
// job produced is compared with the one published on the `feeds` branch, and an implausible
// change is not signed. The build job runs dependency code; this script runs in the publish job
// with plain node (only node:* imports, nothing installed), checked out from the run's commit and
// never taken from the build artifact.
//
//   node scripts/feeds-guard.mjs <new manifest.json> <published manifest.json>
//
// Exit 0: sign. Exit 1: refused, with the reasons; a missing or unreadable published manifest is
// a refusal too. FEEDS_GUARD_OVERRIDE=1 (the workflow's manual `override` input, set by a person
// who reviewed the reasons) publishes anyway and prints them as warnings.
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

function load(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [nextPath, publishedPath] = process.argv.slice(2);
  if (!nextPath || !publishedPath) {
    console.error("usage: node scripts/feeds-guard.mjs <new manifest.json> <published manifest.json>");
    process.exit(2);
  }
  const next = load(nextPath);
  const reasons = feedsGuard(next, load(publishedPath));
  if (reasons.length === 0) {
    console.log(`feeds guard: ok (MetaMask ${next.metamask.as_of}, ${next.metamask.entries} entries; OFAC ${next.ofac.publish_date}, ${next.ofac.addresses} addresses)`);
  } else if (process.env.FEEDS_GUARD_OVERRIDE === "1") {
    for (const r of reasons) console.log(`::warning title=feeds guard (overridden)::${r}`);
  } else {
    for (const r of reasons) console.log(`::error title=feeds guard::${r}`);
    console.log("Not signed. Review the change; to publish it anyway, run the workflow by hand with `override`.");
    process.exit(1);
  }
}

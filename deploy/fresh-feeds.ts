// Runtime refresh of the public feeds (MetaMask phishing list, OFAC SDN addresses)
// without a redeploy. The daily workflow publishes them on the repository's `feeds`
// branch (scripts/publish-feeds.ts) with an Ed25519-signed manifest. The Worker checks
// at most hourly and only swaps in data that:
//   - carries a valid signature from the pinned publisher key (FEEDS_PUBLIC_KEY),
//   - is newer than what it has, with a sane date (not in the future),
//   - matches the manifest (SHA-256 of every file, exact entry counts),
//   - has not shrunk sharply against the list currently in use.
// Anything else keeps the current list (at worst, the snapshot embedded at deploy).
// A cold isolate waits briefly for the first refresh; every attestation states the
// list date it used.
import { hashSetFromBytes, feedHost, type LoadedFeed } from "../src/threat-intel.js";
import { sanctionsListMeta, setSanctionsList, type SanctionsRow } from "../src/sanctions.js";
import type { ExecutionContext, WorkerEnv } from "./runtime.js";

export const DEFAULT_FEEDS_URL = "https://raw.githubusercontent.com/caiovicentino/jev-risk-check-provider/feeds/";
/**
 * Ed25519 public key (raw, base64url) of the feeds publisher. The private key lives only in the
 * `feeds` environment's secret (main only); rotated 2026-09-30, when it moved there.
 */
export const FEEDS_PUBLIC_KEY = "EYQvAYHDsXkqLXXmItsBqtgZc3nZxR2bK8uBevilQRw";
const OK_INTERVAL_MS = 60 * 60 * 1000;
const RETRY_INTERVAL_MS = 10 * 60 * 1000;
const COLD_START_WAIT_MS = 400;
const MIN_METAMASK_RATIO = 0.9;
const MIN_OFAC_RATIO = 0.8;
const MAX_ALLOWLIST = 500;

type Manifest = {
  format: number;
  generated_at: string;
  metamask?: { as_of: string; entries: number; bin_sha256: string; json_sha256: string };
  ofac?: { publish_date: string; addresses: number; json_sha256: string };
};

export type FreshMetamask = LoadedFeed & { allow: ReadonlySet<string>; entries: number };
export type FreshState = { metamask?: FreshMetamask; checked_at?: string; generated_at?: string; error?: string };
export type Baseline = { metamaskAsOf: string; metamaskEntries: number; ofacRows: number };

let state: FreshState = {};
let lastAttempt = 0;
let lastOk = false;
let firstRefresh: Promise<unknown> | null = null;

export function freshFeeds(): FreshState {
  return state;
}

async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64urlBytes(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Verifies an Ed25519 signature (base64 or base64url text) over the exact manifest bytes. */
export async function verifyManifest(manifest: ArrayBuffer, signature: string, publicKey = FEEDS_PUBLIC_KEY): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64urlBytes(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, b64urlBytes(signature.trim()), manifest);
  } catch {
    return false;
  }
}

/** A YYYY-MM-DD date that is not later than tomorrow (UTC). */
export function saneDate(d: unknown, now = Date.now()): d is string {
  if (typeof d !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const t = Date.parse(`${d}T00:00:00Z`);
  return Number.isFinite(t) && t <= now + 24 * 60 * 60 * 1000;
}

async function get(base: string, name: string, fetchImpl: typeof fetch): Promise<ArrayBuffer> {
  // Edge-cache successes for an hour; never cache a miss (a 404 before the first publish would otherwise stick).
  const init = { signal: AbortSignal.timeout(8000), cf: { cacheEverything: true, cacheTtlByStatus: { "200-299": 3600, "300-599": 0 } } } as RequestInit;
  // An hourly cache key: the edge never serves a copy older than the refresh interval,
  // even if an older response was cached under different settings.
  const url = new URL(name, base);
  url.searchParams.set("h", String(Math.floor(Date.now() / 3_600_000)));
  const res = await fetchImpl(url.toString(), init);
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.arrayBuffer();
}

/** Fetches, verifies and applies newer feeds. Exported for tests (inject fetch, key and baselines). */
export async function refreshFeeds(base: string, embedded: Baseline, fetchImpl: typeof fetch = (input, init) => fetch(input, init), publicKey = FEEDS_PUBLIC_KEY): Promise<FreshState> {
  const [manifestBytes, sig] = await Promise.all([get(base, "manifest.json", fetchImpl), get(base, "manifest.sig", fetchImpl)]);
  if (!(await verifyManifest(manifestBytes, new TextDecoder().decode(sig), publicKey))) throw new Error("manifest: signature invalid");
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as Manifest;
  if (manifest.format !== 1) throw new Error(`unknown feeds format ${manifest.format}`);
  const next: FreshState = { ...state, checked_at: new Date().toISOString(), generated_at: manifest.generated_at };
  delete next.error;
  const errors: string[] = [];

  const mm = manifest.metamask;
  const current = state.metamask ?? { as_of: embedded.metamaskAsOf, entries: embedded.metamaskEntries };
  if (mm && saneDate(mm.as_of) && mm.as_of > current.as_of) {
    try {
      const [bin, json] = await Promise.all([get(base, "metamask-phishing.bin", fetchImpl), get(base, "metamask.json", fetchImpl)]);
      if ((await sha256Hex(bin)) !== mm.bin_sha256 || (await sha256Hex(json)) !== mm.json_sha256) throw new Error("metamask: checksum mismatch");
      if (bin.byteLength % 8 !== 0 || bin.byteLength / 8 !== mm.entries) throw new Error("metamask: entry count mismatch");
      if (mm.entries < current.entries * MIN_METAMASK_RATIO) throw new Error(`metamask: ${mm.entries} entries is a large shrink`);
      const parsed = JSON.parse(new TextDecoder().decode(json)) as { allowlist?: unknown };
      const allow = Array.isArray(parsed.allowlist) ? parsed.allowlist.filter((h): h is string => typeof h === "string" && h === feedHost(h) && /^[a-z0-9.-]{3,253}$/.test(h)) : [];
      if (allow.length > MAX_ALLOWLIST) throw new Error(`metamask: ${allow.length} allowlisted hosts is implausible`);
      next.metamask = { set: hashSetFromBytes(bin), as_of: mm.as_of, allow: new Set(allow), entries: mm.entries };
    } catch (err) {
      errors.push(String(err instanceof Error ? err.message : err));
    }
  } else if (mm && !saneDate(mm.as_of)) errors.push("metamask: implausible date");

  const of = manifest.ofac;
  const ofacNow = sanctionsListMeta();
  if (of && saneDate(of.publish_date) && of.publish_date > ofacNow.publish_date) {
    try {
      const json = await get(base, "ofac-sdn.json", fetchImpl);
      if ((await sha256Hex(json)) !== of.json_sha256) throw new Error("ofac: checksum mismatch");
      const parsed = JSON.parse(new TextDecoder().decode(json)) as { meta?: { source?: unknown }; rows?: unknown };
      const rows = Array.isArray(parsed.rows) ? parsed.rows : [];
      const valid = rows.every((r): r is SanctionsRow => Array.isArray(r) && r.length === 4 && typeof r[0] === "string" && r[0].length > 0 && r[0].length <= 128 && typeof r[1] === "string" && typeof r[2] === "number" && typeof r[3] === "string");
      if (!valid || rows.length !== of.addresses) throw new Error("ofac: malformed rows");
      if (rows.length < Math.max(embedded.ofacRows, ofacNow.addresses) * MIN_OFAC_RATIO) throw new Error(`ofac: ${rows.length} addresses is a large shrink`);
      setSanctionsList(rows as SanctionsRow[], { source: typeof parsed.meta?.source === "string" ? parsed.meta.source : "OFAC SDN", publish_date: of.publish_date });
    } catch (err) {
      errors.push(String(err instanceof Error ? err.message : err));
    }
  } else if (of && !saneDate(of.publish_date)) errors.push("ofac: implausible date");
  state = errors.length ? { ...next, error: errors.join("; ").slice(0, 300) } : next;
  if (errors.length) throw new Error(state.error);
  return state;
}

/**
 * Starts a refresh when one is due, in the background. Returns a promise the caller
 * may briefly await on a cold isolate (so the first screen uses the newest verified
 * list when it is quickly available); it never rejects.
 */
export function maybeRefreshFeeds(env: WorkerEnv, ctx: ExecutionContext | undefined, embedded: Baseline): Promise<void> {
  const base = env.FEEDS_URL ?? DEFAULT_FEEDS_URL;
  if (base === "off" || !ctx) return Promise.resolve();
  const now = Date.now();
  if (now - lastAttempt < (lastOk ? OK_INTERVAL_MS : RETRY_INTERVAL_MS)) return Promise.resolve();
  lastAttempt = now;
  const run = refreshFeeds(base, embedded).then(
    () => {
      lastOk = true;
    },
    (err: unknown) => {
      lastOk = false;
      state = { ...state, checked_at: new Date().toISOString(), error: String(err instanceof Error ? err.message : err).slice(0, 300) };
    },
  );
  ctx.waitUntil(run);
  if (!firstRefresh) firstRefresh = run;
  return run;
}

/** On a cold isolate, wait up to COLD_START_WAIT_MS for the first refresh. */
export async function awaitColdStart(): Promise<void> {
  if (!firstRefresh) return;
  const first = firstRefresh;
  await Promise.race([first, new Promise((r) => setTimeout(r, COLD_START_WAIT_MS))]);
}

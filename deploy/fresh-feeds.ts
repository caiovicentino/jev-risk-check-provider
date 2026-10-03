// Runtime refresh of the public feeds (MetaMask phishing list, OFAC SDN addresses)
// without a redeploy. The daily workflow publishes them on the repository's `feeds`
// branch (scripts/publish-feeds.ts) with an Ed25519-signed manifest. The Worker checks
// at most hourly and only swaps in data that:
//   - carries a valid signature from the pinned publisher key (FEEDS_PUBLIC_KEY),
//   - is newer than what it has, with a sane date (not in the future),
//   - matches the manifest (SHA-256 of every file, exact entry counts),
//   - has not shrunk sharply against the list currently in use.
// Anything else keeps the current list (at worst, the snapshot embedded at deploy).
//
// OFAC comes first, and fast: the last verified release is kept in KV (`feed:ofac:v1`: the
// signed manifest, its signature and the snapshot, re-verified on every load, so KV is never
// trusted on its own), written once per release by whichever isolate verifies it first. A new
// isolate loads it with one KV read before anything else, and the network refresh fetches
// OFAC before the larger MetaMask list. A paid request on a cold isolate waits up to 2.5 s for
// a current OFAC list (warm isolates never wait); past that it proceeds on the list it has, and
// every attestation states the list date it used.
import { hashSetFromBytes, feedHost, type LoadedFeed } from "../src/threat-intel.js";
import { artifactDigest, sanctionsListMeta, setSanctionsList, type SanctionsRow } from "../src/sanctions.js";
import type { ExecutionContext, WorkerEnv } from "./runtime.js";

export const DEFAULT_FEEDS_URL = "https://raw.githubusercontent.com/caiovicentino/jev-risk-check-provider/feeds/";
/**
 * Ed25519 public key (raw, base64url) of the feeds publisher. The private key lives only in the
 * `feeds` environment's secret (main only); rotated 2026-09-30, when it moved there.
 */
export const FEEDS_PUBLIC_KEY = "EYQvAYHDsXkqLXXmItsBqtgZc3nZxR2bK8uBevilQRw";
const OK_INTERVAL_MS = 60 * 60 * 1000;
const RETRY_INTERVAL_MS = 10 * 60 * 1000;
/** A paid request on a cold isolate waits at most this long for a current OFAC list. */
const COLD_START_WAIT_MS = 2500;
/** The last verified OFAC release, for new isolates: { manifest, sig, ofac } as published. */
export const OFAC_KV_KEY = "feed:ofac:v1";
const MIN_METAMASK_RATIO = 0.9;
const MIN_OFAC_RATIO = 0.8;
const MAX_ALLOWLIST = 500;

type Manifest = {
  format: number;
  generated_at: string;
  metamask?: { as_of: string; entries: number; bin_sha256: string; json_sha256: string };
  /** `xml_sha256`: SHA-256 of the SDN.XML the snapshot was built from (manifests since 2026-10-01). */
  ofac?: { publish_date: string; addresses: number; json_sha256: string; xml_sha256?: string };
};

export type FreshMetamask = LoadedFeed & { allow: ReadonlySet<string>; entries: number };
export type FreshState = { metamask?: FreshMetamask; checked_at?: string; generated_at?: string; error?: string };
export type Baseline = { metamaskAsOf: string; metamaskEntries: number; ofacRows: number };

export type FeedsKv = { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void> };
type OfacBundle = { manifest: string; sig: string; ofac: string };

let state: FreshState = {};
let lastAttempt = 0;
let lastOk = false;
/** Resolves once this isolate screens against a current OFAC list (from KV or the network). */
let ofacReady: Promise<void> | null = null;
let ofacCurrent = false;
let markOfacReady: (() => void) | null = null;
/** The release KV holds, once read (null: none). */
let kvRead: Promise<string | null> | null = null;
/** Set once a cold wait ran out: this isolate then stops waiting (a down network must not slow every check). */
let coldWaitOver = false;

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

/** A published OFAC snapshot checked against its signed manifest entry: what setSanctionsList takes. */
async function verifiedOfac(of: NonNullable<Manifest["ofac"]>, json: ArrayBuffer, embedded: Baseline): Promise<{ rows: SanctionsRow[]; meta: { source: string; publish_date: string; digest?: string } }> {
  if ((await sha256Hex(json)) !== of.json_sha256) throw new Error("ofac: checksum mismatch");
  const parsed = JSON.parse(new TextDecoder().decode(json)) as { meta?: { source?: unknown; sha256?: unknown }; rows?: unknown };
  const rows = Array.isArray(parsed.rows) ? parsed.rows : [];
  const valid = rows.every((r): r is SanctionsRow => Array.isArray(r) && r.length === 4 && typeof r[0] === "string" && r[0].length > 0 && r[0].length <= 128 && typeof r[1] === "string" && typeof r[2] === "number" && typeof r[3] === "string");
  if (!valid || rows.length !== of.addresses) throw new Error("ofac: malformed rows");
  if (rows.length < Math.max(embedded.ofacRows, sanctionsListMeta().addresses) * MIN_OFAC_RATIO) throw new Error(`ofac: ${rows.length} addresses is a large shrink`);
  // The SDN.XML digest, from the signed manifest and the checksummed snapshot: both must agree when both say.
  const fromManifest = artifactDigest(of.xml_sha256);
  const fromSnapshot = artifactDigest(parsed.meta?.sha256);
  if (fromManifest && fromSnapshot && fromManifest !== fromSnapshot) throw new Error("ofac: source digest mismatch");
  const digest = fromManifest ?? fromSnapshot;
  return { rows: rows as SanctionsRow[], meta: { source: typeof parsed.meta?.source === "string" ? parsed.meta.source : "OFAC SDN", publish_date: of.publish_date, ...(digest ? { digest } : {}) } };
}

/**
 * The last verified OFAC release kept in KV, verified again (signature with the pinned key,
 * checksum, rows) and applied when newer than the list in use. Returns the release date KV
 * holds, or null when it holds none. Exported for tests.
 */
export async function loadOfacFromKv(kv: FeedsKv, embedded: Baseline, publicKey = FEEDS_PUBLIC_KEY): Promise<string | null> {
  const raw = await kv.get(OFAC_KV_KEY);
  if (!raw) return null;
  const bundle = JSON.parse(raw) as Partial<OfacBundle>;
  if (typeof bundle.manifest !== "string" || typeof bundle.sig !== "string" || typeof bundle.ofac !== "string") throw new Error("kv ofac: malformed bundle");
  if (!(await verifyManifest(new TextEncoder().encode(bundle.manifest).buffer, bundle.sig, publicKey))) throw new Error("kv ofac: signature invalid");
  const manifest = JSON.parse(bundle.manifest) as Manifest;
  const of = manifest.ofac;
  if (manifest.format !== 1 || !of || !saneDate(of.publish_date)) throw new Error("kv ofac: no plausible release");
  if (of.publish_date > sanctionsListMeta().publish_date) {
    const verified = await verifiedOfac(of, new TextEncoder().encode(bundle.ofac).buffer, embedded);
    setSanctionsList(verified.rows, verified.meta);
  }
  return of.publish_date;
}

export type RefreshOptions = {
  /** Where the last verified OFAC release is kept for new isolates. */
  kv?: FeedsKv | undefined;
  /** The release KV holds (null: none), once this isolate has read it. */
  kvDate?: (() => Promise<string | null>) | undefined;
  /** Called once the OFAC step is over, whatever its outcome. */
  onOfac?: (() => void) | undefined;
};

/** Fetches, verifies and applies newer feeds, OFAC first. Exported for tests (inject fetch, key, baselines and KV). */
export async function refreshFeeds(base: string, embedded: Baseline, fetchImpl: typeof fetch = (input, init) => fetch(input, init), publicKey = FEEDS_PUBLIC_KEY, opts: RefreshOptions = {}): Promise<FreshState> {
  let manifest: Manifest;
  let manifestText: string;
  let sigText: string;
  try {
    const [manifestBytes, sig] = await Promise.all([get(base, "manifest.json", fetchImpl), get(base, "manifest.sig", fetchImpl)]);
    sigText = new TextDecoder().decode(sig);
    if (!(await verifyManifest(manifestBytes, sigText, publicKey))) throw new Error("manifest: signature invalid");
    manifestText = new TextDecoder().decode(manifestBytes);
    manifest = JSON.parse(manifestText) as Manifest;
    if (manifest.format !== 1) throw new Error(`unknown feeds format ${manifest.format}`);
  } catch (err) {
    opts.onOfac?.();
    throw err;
  }
  const next: FreshState = { ...state, checked_at: new Date().toISOString(), generated_at: manifest.generated_at };
  delete next.error;
  const errors: string[] = [];

  // OFAC first: it is small, and it is what a paid request on a cold isolate waits for.
  const of = manifest.ofac;
  try {
    if (of && saneDate(of.publish_date)) {
      const newer = of.publish_date > sanctionsListMeta().publish_date;
      // KV is written once per release, and only forward: when it holds nothing or an older release
      // (a stale CDN copy of the manifest never overwrites a newer one).
      const held = opts.kv ? await (opts.kvDate?.() ?? Promise.resolve(null)) : null;
      const kvBehind = !!opts.kv && (held === null || of.publish_date > held);
      if (newer || kvBehind) {
        const json = await get(base, "ofac-sdn.json", fetchImpl);
        const verified = await verifiedOfac(of, json, embedded);
        if (newer) setSanctionsList(verified.rows, verified.meta);
        if (kvBehind && opts.kv) {
          await opts.kv.put(OFAC_KV_KEY, JSON.stringify({ manifest: manifestText, sig: sigText, ofac: new TextDecoder().decode(json) } satisfies OfacBundle));
          kvRead = Promise.resolve(of.publish_date);
        }
      }
    } else if (of) errors.push("ofac: implausible date");
  } catch (err) {
    errors.push(String(err instanceof Error ? err.message : err));
  } finally {
    opts.onOfac?.();
  }

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

  state = errors.length ? { ...next, error: errors.join("; ").slice(0, 300) } : next;
  if (errors.length) throw new Error(state.error);
  return state;
}

/**
 * Starts a refresh when one is due, in the background, and, on a new isolate, the load of the
 * last verified OFAC release from KV first. Returns a promise that never rejects.
 */
export function maybeRefreshFeeds(env: WorkerEnv, ctx: ExecutionContext | undefined, embedded: Baseline, inject: { fetchImpl?: typeof fetch; publicKey?: string } = {}): Promise<void> {
  const base = env.FEEDS_URL ?? DEFAULT_FEEDS_URL;
  if (base === "off" || !ctx) return Promise.resolve();
  const kv = env.RATE && typeof env.RATE.put === "function" ? (env.RATE as FeedsKv) : undefined;
  if (!ofacReady) {
    // A new isolate: current once KV yields a verified release, or once the network's OFAC step is over.
    ofacReady = new Promise<void>((resolve) => {
      markOfacReady = resolve;
    }).then(() => {
      ofacCurrent = true;
    });
    kvRead = kv
      ? loadOfacFromKv(kv, embedded, inject.publicKey).then(
          (date) => {
            if (date) markOfacReady?.();
            return date;
          },
          (err: unknown) => {
            console.error(`feeds: the OFAC release in KV was not used (${String(err instanceof Error ? err.message : err).slice(0, 120)})`);
            return null;
          },
        )
      : Promise.resolve(null);
    ctx.waitUntil(kvRead);
  }
  const now = Date.now();
  if (now - lastAttempt < (lastOk ? OK_INTERVAL_MS : RETRY_INTERVAL_MS)) return Promise.resolve();
  lastAttempt = now;
  const run = refreshFeeds(base, embedded, inject.fetchImpl, inject.publicKey, { kv, kvDate: () => kvRead ?? Promise.resolve(null), onOfac: () => markOfacReady?.() }).then(
    () => {
      lastOk = true;
    },
    (err: unknown) => {
      lastOk = false;
      state = { ...state, checked_at: new Date().toISOString(), error: String(err instanceof Error ? err.message : err).slice(0, 300) };
    },
  );
  ctx.waitUntil(run);
  return run;
}

/**
 * A paid request on a cold isolate waits up to COLD_START_WAIT_MS for a current OFAC list;
 * a warm isolate never waits. Past the wait it proceeds on the list it has (the attestation
 * states its date), says so once, and the isolate stops waiting.
 */
export async function awaitColdStart(): Promise<void> {
  if (!ofacReady || ofacCurrent || coldWaitOver) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = await Promise.race([ofacReady.then(() => false), new Promise<boolean>((resolve) => (timer = setTimeout(() => resolve(true), COLD_START_WAIT_MS)))]);
  clearTimeout(timer);
  if (timedOut && !coldWaitOver) {
    coldWaitOver = true;
    console.warn(`feeds: a paid check went ahead on the ${sanctionsListMeta().publish_date} OFAC list after waiting ${COLD_START_WAIT_MS} ms for a current one`);
  }
}

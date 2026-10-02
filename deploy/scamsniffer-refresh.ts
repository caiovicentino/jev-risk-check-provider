// Daily ScamSniffer refresh, run by the Worker's cron. The data is GPL-3.0: it is fetched at
// runtime into the operator's KV and never committed, bundled or published (as with the manual
// `scripts/update-threat-feeds.ts --scamsniffer --upload`). Domains and EVM addresses are rebuilt
// from the published lists; the code fingerprints (thousands of eth_getCode calls) stay a manual
// build, and their own date is kept apart (`code_as_of`).
//
// The domain list is ~9 MB of JSON: it is parsed as a stream and hashed on the fly, so the
// isolate (which also runs the kit watch) never holds the whole list.
//
// Supply chain: the upstream head commit is resolved first and both lists are read at that SHA,
// so the data and the recorded commit always agree; a list that shrinks or grows implausibly in
// one refresh is refused (the previous data stays, and the reason is logged); and addresses that
// must never be flagged (src/never-flag.ts) are dropped before hashing.
import { neverFlag } from "../src/never-flag.js";
import { feedHash, normalizeFeedDomain } from "../src/threat-intel.js";
import type { WorkerEnv } from "./runtime.js";

const REPO = "scamsniffer/scam-database";
/** A list file at a commit SHA (or at `main` when the commit lookup failed). */
const listUrl = (ref: string, file: "domains.json" | "address.json"): string => `https://raw.githubusercontent.com/${REPO}/${ref}/blacklist/${file}`;
export const SCAMSNIFFER_KEYS = { domains: "feed:scamsniffer:domains:v1", addresses: "feed:scamsniffer:addresses:v1", code: "feed:scamsniffer:code:v1", meta: "feed:scamsniffer:meta:v1" };
/** A list that shrank below this share of the previous one is a broken download, not news: kept as is. */
const MIN_KEEP = 0.5;
/**
 * Growth past either bound in one refresh (twice a day) is a poisoned or broken list, not news:
 * kept as is. A large legitimate import goes in through the manual build after review.
 */
const MAX_GROWTH = 0.5;
const MAX_NEW = { domains: 100_000, addresses: 2_000 } as const;
const MAX_BYTES = 64 * 1024 * 1024;

/** Each string of a JSON array of strings, read from a byte stream without buffering it whole. */
export async function* jsonStrings(body: ReadableStream<Uint8Array>, maxBytes = MAX_BYTES): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  const reader = body.getReader();
  let inString = false;
  let escaped = false;
  let hasEscape = false;
  let current = "";
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (value) {
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`list larger than ${maxBytes} bytes`);
      }
    }
    const text = decoder.decode(value, { stream: !done });
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      const ch = text.charCodeAt(i);
      if (!inString) {
        if (ch === 34 /* " */) {
          inString = true;
          current = "";
          hasEscape = false;
          start = i + 1;
        }
        continue;
      }
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === 92 /* \ */) {
        escaped = true;
        hasEscape = true;
        continue;
      }
      if (ch === 34) {
        current += text.slice(start, i);
        inString = false;
        yield hasEscape ? (JSON.parse(`"${current}"`) as string) : current;
      }
    }
    if (inString) current += text.slice(start);
    if (done) break;
  }
  if (inString) throw new Error("truncated JSON: unterminated string");
}

/** The sorted, de-duplicated hash blob (the format of buildHashBlob), built incrementally. */
class HashBlobBuilder {
  private values = new BigUint64Array(1 << 16);
  private n = 0;
  add(value: string): void {
    if (this.n === this.values.length) {
      const grown = new BigUint64Array(this.values.length * 2);
      grown.set(this.values);
      this.values = grown;
    }
    this.values[this.n++] = feedHash(value);
  }
  build(): Uint8Array {
    const sorted = this.values.subarray(0, this.n).sort();
    const out = new Uint8Array(this.n * 8);
    const view = new DataView(out.buffer);
    let k = 0;
    for (let i = 0; i < sorted.length; i++) {
      const v = sorted[i] as bigint;
      if (i > 0 && v === sorted[i - 1]) continue;
      view.setBigUint64(k * 8, v);
      k++;
    }
    return out.slice(0, k * 8);
  }
}

type Meta = { as_of?: string; code_as_of?: string; commit?: string; domains?: number; addresses?: number; code_fingerprints?: number; [k: string]: unknown };

/** `never_flag_dropped`: listed addresses that must never be flagged (src/never-flag.ts), left out. */
export type RefreshResult = { status: "updated"; domains: number; addresses: number; never_flag_dropped: number } | { status: "kept"; reason: string };

/** The list repository's head commit, or null when GitHub does not answer (unauthenticated lookups can be rate-limited). */
async function headCommit(fetchImpl: typeof fetch): Promise<{ sha: string; date: string } | null> {
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${REPO}/commits/main`, { headers: { Accept: "application/vnd.github+json", "User-Agent": "x402check-feeds" } });
    if (!res.ok) return null;
    const c = (await res.json()) as { sha?: unknown; commit?: { committer?: { date?: unknown } } };
    const date = typeof c.commit?.committer?.date === "string" ? c.commit.committer.date.slice(0, 10) : "";
    // The SHA becomes part of the list URLs: only a full lowercase hex SHA is used.
    return typeof c.sha === "string" && /^[0-9a-f]{40}$/.test(c.sha) && /^\d{4}-\d{2}-\d{2}$/.test(date) ? { sha: c.sha, date } : null;
  } catch {
    return null;
  }
}

/** Rebuilds the ScamSniffer domain and address sets in KV; the code set and its date are kept. */
export async function refreshScamSniffer(env: WorkerEnv, fetchImpl: typeof fetch = fetch, now = new Date()): Promise<RefreshResult> {
  const kv = env.RATE;
  if (!kv) return { status: "kept", reason: "no KV binding" };
  const prevRaw = await kv.get(SCAMSNIFFER_KEYS.meta);
  const prev = prevRaw ? (JSON.parse(prevRaw) as Meta) : null;

  // Resolve the commit first and read both lists at it; `main` and the fetch date only when GitHub does not answer.
  const commit = await headCommit(fetchImpl);
  const ref = commit?.sha ?? "main";
  const domainsRes = await fetchImpl(listUrl(ref, "domains.json"));
  if (!domainsRes.ok || !domainsRes.body) return { status: "kept", reason: `domains.json: HTTP ${domainsRes.status}` };
  const domains = new HashBlobBuilder();
  for await (const entry of jsonStrings(domainsRes.body)) {
    const host = normalizeFeedDomain(entry);
    if (host) domains.add(host);
  }
  const addressesRes = await fetchImpl(listUrl(ref, "address.json"));
  if (!addressesRes.ok || !addressesRes.body) return { status: "kept", reason: `address.json: HTTP ${addressesRes.status}` };
  const ours = env.PAY_TO_EVM ? new Set([env.PAY_TO_EVM.toLowerCase()]) : undefined;
  const addresses = new HashBlobBuilder();
  let dropped = 0;
  for await (const entry of jsonStrings(addressesRes.body)) {
    const s = entry.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(s)) continue;
    if (neverFlag(s, ours)) dropped++;
    else addresses.add(s.toLowerCase());
  }
  const dBlob = domains.build();
  const aBlob = addresses.build();
  const counts = { domains: dBlob.byteLength / 8, addresses: aBlob.byteLength / 8 };
  for (const kind of ["domains", "addresses"] as const) {
    const before = prev?.[kind];
    if (!before) continue;
    if (counts[kind] < before * MIN_KEEP) return { status: "kept", reason: `${kind} shrank from ${before} to ${counts[kind]}` };
    if (counts[kind] > before * (1 + MAX_GROWTH) || counts[kind] - before > MAX_NEW[kind]) return { status: "kept", reason: `${kind} grew from ${before} to ${counts[kind]}` };
  }
  if (counts.domains < 1000) return { status: "kept", reason: `only ${counts.domains} domains: format changed?` };

  await kv.put(SCAMSNIFFER_KEYS.domains, dBlob);
  await kv.put(SCAMSNIFFER_KEYS.addresses, aBlob);
  const meta: Meta = {
    ...(prev ?? {}),
    source: `https://github.com/${REPO}`,
    license: "GPL-3.0 (runtime use only; not distributed)",
    as_of: commit?.date ?? now.toISOString().slice(0, 10),
    as_of_source: commit ? "commit" : "fetched",
    // The code fingerprints were built by the manual script: they keep their own date.
    ...(prev?.code_fingerprints !== undefined ? { code_as_of: prev.code_as_of ?? prev.as_of } : {}),
    refreshed_at: now.toISOString(),
    domains: counts.domains,
    addresses: counts.addresses,
    never_flag_dropped: dropped,
    note: "public data is published with a 7-day delay",
  };
  // Read from `main` at an unknown commit: an earlier refresh's SHA would misdescribe this data.
  if (commit) meta.commit = commit.sha;
  else delete meta.commit;
  await kv.put(SCAMSNIFFER_KEYS.meta, JSON.stringify(meta));
  return { status: "updated", ...counts, never_flag_dropped: dropped };
}

/** The cron's hook: at 05:37 and 17:37 UTC. */
export async function maybeRefreshScamSniffer(env: WorkerEnv, scheduledTime: number): Promise<void> {
  const t = new Date(scheduledTime);
  if (t.getUTCMinutes() !== 37 || (t.getUTCHours() !== 5 && t.getUTCHours() !== 17)) return;
  const result = await refreshScamSniffer(env);
  if (result.status === "kept") {
    console.error(`scamsniffer refresh kept the previous data: ${result.reason}`);
    return;
  }
  console.log(`scamsniffer refreshed: ${result.domains} domains, ${result.addresses} addresses`);
  if (result.never_flag_dropped > 0) console.error(`scamsniffer lists ${result.never_flag_dropped} never-flag address(es): left out`);
}

// Daily ScamSniffer refresh, run by the Worker's cron. The data is GPL-3.0: it is fetched at
// runtime into the operator's KV and never committed, bundled or published (as with the manual
// `scripts/update-threat-feeds.ts --scamsniffer --upload`). Domains and EVM addresses are rebuilt
// from the published lists; the code fingerprints (thousands of eth_getCode calls) stay a manual
// build, and their own date is kept apart (`code_as_of`).
//
// The domain list is ~9 MB of JSON: it is parsed as a stream and hashed on the fly, so the
// isolate (which also runs the kit watch) never holds the whole list.
import { feedHash, normalizeFeedDomain } from "../src/threat-intel.js";
import type { WorkerEnv } from "./runtime.js";

const REPO = "scamsniffer/scam-database";
const DOMAINS_URL = `https://raw.githubusercontent.com/${REPO}/main/blacklist/domains.json`;
const ADDRESSES_URL = `https://raw.githubusercontent.com/${REPO}/main/blacklist/address.json`;
export const SCAMSNIFFER_KEYS = { domains: "feed:scamsniffer:domains:v1", addresses: "feed:scamsniffer:addresses:v1", code: "feed:scamsniffer:code:v1", meta: "feed:scamsniffer:meta:v1" };
/** A list that shrank below this share of the previous one is a broken download, not news: kept as is. */
const MIN_KEEP = 0.5;
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

export type RefreshResult = { status: "updated"; domains: number; addresses: number } | { status: "kept"; reason: string };

/** Rebuilds the ScamSniffer domain and address sets in KV; the code set and its date are kept. */
export async function refreshScamSniffer(env: WorkerEnv, fetchImpl: typeof fetch = fetch, now = new Date()): Promise<RefreshResult> {
  const kv = env.RATE;
  if (!kv) return { status: "kept", reason: "no KV binding" };
  const prevRaw = await kv.get(SCAMSNIFFER_KEYS.meta);
  const prev = prevRaw ? (JSON.parse(prevRaw) as Meta) : null;

  const domainsRes = await fetchImpl(DOMAINS_URL);
  if (!domainsRes.ok || !domainsRes.body) return { status: "kept", reason: `domains.json: HTTP ${domainsRes.status}` };
  const domains = new HashBlobBuilder();
  for await (const entry of jsonStrings(domainsRes.body)) {
    const host = normalizeFeedDomain(entry);
    if (host) domains.add(host);
  }
  const addressesRes = await fetchImpl(ADDRESSES_URL);
  if (!addressesRes.ok) return { status: "kept", reason: `address.json: HTTP ${addressesRes.status}` };
  const addresses = new HashBlobBuilder();
  for (const a of (await addressesRes.json()) as unknown[]) {
    const s = String(a).trim();
    if (/^0x[0-9a-fA-F]{40}$/.test(s)) addresses.add(s.toLowerCase());
  }
  const dBlob = domains.build();
  const aBlob = addresses.build();
  const counts = { domains: dBlob.byteLength / 8, addresses: aBlob.byteLength / 8 };
  if (prev?.domains && counts.domains < prev.domains * MIN_KEEP) return { status: "kept", reason: `domains shrank from ${prev.domains} to ${counts.domains}` };
  if (prev?.addresses && counts.addresses < prev.addresses * MIN_KEEP) return { status: "kept", reason: `addresses shrank from ${prev.addresses} to ${counts.addresses}` };
  if (counts.domains < 1000) return { status: "kept", reason: `only ${counts.domains} domains: format changed?` };

  // The list's commit date when GitHub answers (unauthenticated lookups can be rate-limited), else the fetch date.
  let commit: { sha: string; date: string } | null = null;
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${REPO}/commits/main`, { headers: { Accept: "application/vnd.github+json", "User-Agent": "x402check-feeds" } });
    if (res.ok) {
      const c = (await res.json()) as { sha?: string; commit?: { committer?: { date?: string } } };
      if (c.sha && c.commit?.committer?.date) commit = { sha: c.sha, date: c.commit.committer.date.slice(0, 10) };
    }
  } catch {
    // keep the fetch date
  }
  await kv.put(SCAMSNIFFER_KEYS.domains, dBlob);
  await kv.put(SCAMSNIFFER_KEYS.addresses, aBlob);
  const meta: Meta = {
    ...(prev ?? {}),
    source: `https://github.com/${REPO}`,
    license: "GPL-3.0 (runtime use only; not distributed)",
    ...(commit ? { commit: commit.sha } : {}),
    as_of: commit?.date ?? now.toISOString().slice(0, 10),
    as_of_source: commit ? "commit" : "fetched",
    // The code fingerprints were built by the manual script: they keep their own date.
    ...(prev?.code_fingerprints !== undefined ? { code_as_of: prev.code_as_of ?? prev.as_of } : {}),
    refreshed_at: now.toISOString(),
    domains: counts.domains,
    addresses: counts.addresses,
    note: "public data is published with a 7-day delay",
  };
  await kv.put(SCAMSNIFFER_KEYS.meta, JSON.stringify(meta));
  return { status: "updated", ...counts };
}

/** The cron's hook: at 05:37 and 17:37 UTC. */
export async function maybeRefreshScamSniffer(env: WorkerEnv, scheduledTime: number): Promise<void> {
  const t = new Date(scheduledTime);
  if (t.getUTCMinutes() !== 37 || (t.getUTCHours() !== 5 && t.getUTCHours() !== 17)) return;
  const result = await refreshScamSniffer(env);
  if (result.status === "kept") console.error(`scamsniffer refresh kept the previous data: ${result.reason}`);
  else console.log(`scamsniffer refreshed: ${result.domains} domains, ${result.addresses} addresses`);
}

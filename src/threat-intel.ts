import { createHash } from "node:crypto";
import { BRANDS } from "./domain-analysis.js";
import type { Subject } from "./address.js";

// Community threat feeds, stored as sorted big-endian uint64 SHA-256 prefixes: no
// parsing at isolate start-up, O(log n) lookups, ~8 bytes per entry. Collision odds
// per lookup ≈ n / 2^64 (≈5e-15 for 100k entries).

export type FeedKind = "domain" | "address" | "code";
export type FeedSource = "metamask-phishing-detect" | "scamsniffer-domains" | "scamsniffer-addresses" | "forta-phishing-code" | "scamsniffer-code" | "x402check-kit-watch";
export type FeedStatus = "hit" | "clear" | "unavailable" | "not_applicable";

export type FeedResult = { source: FeedSource; kind: FeedKind; as_of: string; status: FeedStatus };

export type HashSet = { size: number; has(value: string): boolean };

export function feedHash(value: string): bigint {
  return createHash("sha256").update(value).digest().readBigUInt64BE(0);
}

export function buildHashBlob(values: Iterable<string>): Uint8Array {
  const sorted = [...new Set([...values].map(feedHash))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out = new Uint8Array(sorted.length * 8);
  const view = new DataView(out.buffer);
  sorted.forEach((h, i) => view.setBigUint64(i * 8, h));
  return out;
}

export function hashSetFromBytes(bytes: Uint8Array | ArrayBuffer): HashSet {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u8.byteLength % 8 !== 0) throw new Error("hash blob length must be a multiple of 8");
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const size = u8.byteLength / 8;
  return {
    size,
    has(value: string): boolean {
      const target = feedHash(value);
      let lo = 0;
      let hi = size - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        const v = view.getBigUint64(mid * 8);
        if (v === target) return true;
        if (v < target) lo = mid + 1;
        else hi = mid - 1;
      }
      return false;
    },
  };
}

/** Feed-normalized host: lowercase, no trailing dot, no leading "www.". */
export function feedHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

export type LoadedFeed = { set: HashSet; as_of: string };

export type ThreatIntelFeeds = {
  metamaskDomains?: LoadedFeed | null;
  /** Domains the MetaMask list itself allowlists (feed-normalized). */
  metamaskAllow?: ReadonlySet<string>;
  scamsnifferDomains?: LoadedFeed | null;
  scamsnifferAddresses?: LoadedFeed | null;
  /** Fingerprints of listed drainer contracts' logic code (see code-fingerprint.ts). */
  fortaCode?: LoadedFeed | null;
  scamsnifferCode?: LoadedFeed | null;
};

const OFFICIAL = new Set(Object.values(BRANDS).flat());

export type ThreatCheck = { results: FeedResult[]; hits: FeedResult[] };

/** Official brand domains and MetaMask's own allowlist (legit look-alikes such as opensea.pro). */
export function isAllowlistedDomain(feeds: ThreatIntelFeeds, domain: { host: string; registrable: string }): boolean {
  return OFFICIAL.has(domain.registrable) || (feeds.metamaskAllow?.has(feedHost(domain.registrable)) ?? false) || (feeds.metamaskAllow?.has(feedHost(domain.host)) ?? false);
}

/**
 * Domain: MetaMask entries block the host and its parents down to the registrable
 * domain (the public-suffix boundary, so a listed "x.vercel.app" never blocks
 * vercel.app itself). ScamSniffer (noisier: shared platforms appear in it) is
 * matched on the exact host only. Official brand domains and MetaMask's own
 * allowlist suppress domain hits. Address: ScamSniffer EVM drainer/scam list.
 */
export function checkFeeds(feeds: ThreatIntelFeeds, subject: Subject, domain: { host: string; registrable: string } | null): ThreatCheck {
  const results: FeedResult[] = [];
  const allowlisted = domain ? isAllowlistedDomain(feeds, domain) : false;
  const domainFeed = (source: FeedSource, feed: LoadedFeed | null | undefined, match: (set: HashSet, host: string, registrable: string) => boolean): void => {
    if (feed === undefined) return;
    if (!feed) return void results.push({ source, kind: "domain", as_of: "", status: "unavailable" });
    if (!domain) return void results.push({ source, kind: "domain", as_of: feed.as_of, status: "not_applicable" });
    const hit = !allowlisted && match(feed.set, feedHost(domain.host), feedHost(domain.registrable));
    results.push({ source, kind: "domain", as_of: feed.as_of, status: hit ? "hit" : "clear" });
  };
  domainFeed("metamask-phishing-detect", feeds.metamaskDomains, (set, host, registrable) => {
    const labels = host.split(".");
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join(".");
      if (set.has(candidate)) return true;
      if (candidate === registrable) break;
    }
    return false;
  });
  domainFeed("scamsniffer-domains", feeds.scamsnifferDomains, (set, host) => set.has(host));

  const addr = feeds.scamsnifferAddresses;
  if (addr !== undefined) {
    if (!addr) results.push({ source: "scamsniffer-addresses", kind: "address", as_of: "", status: "unavailable" });
    else if (subject.format !== "evm") results.push({ source: "scamsniffer-addresses", kind: "address", as_of: addr.as_of, status: "not_applicable" });
    else results.push({ source: "scamsniffer-addresses", kind: "address", as_of: addr.as_of, status: addr.set.has(subject.canonical) ? "hit" : "clear" });
  }
  return { results, hits: results.filter((r) => r.status === "hit") };
}

const CODE_FEEDS = [
  ["forta-phishing-code", "fortaCode"],
  ["scamsniffer-code", "scamsnifferCode"],
] as const;

/** The code-fingerprint feeds that list this fingerprint. */
export function matchCode(feeds: ThreatIntelFeeds, fingerprint: string): FeedSource[] {
  return CODE_FEEDS.filter(([, field]) => feeds[field]?.set.has(fingerprint)).map(([source]) => source);
}

/**
 * One result per configured code feed. scope "checked" = at least one contract in
 * scope (the subject, or the called contract, recipients and spenders of a simulated
 * transaction) had fingerprintable logic code; `matched` = sources that listed one.
 */
export function codeFeedResults(feeds: ThreatIntelFeeds, scope: "checked" | "not_applicable" | "unavailable", matched: ReadonlySet<string>): FeedResult[] {
  const results: FeedResult[] = [];
  for (const [source, field] of CODE_FEEDS) {
    const feed = feeds[field];
    if (feed === undefined) continue;
    if (!feed) results.push({ source, kind: "code", as_of: "", status: "unavailable" });
    else results.push({ source, kind: "code", as_of: feed.as_of, status: matched.has(source) ? "hit" : scope === "checked" ? "clear" : scope });
  }
  return results;
}

/** Whether any code-fingerprint feed is configured (loaded or failed). */
export function hasCodeFeeds(feeds: ThreatIntelFeeds): boolean {
  return CODE_FEEDS.some(([, field]) => feeds[field] !== undefined);
}

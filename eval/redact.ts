// Evidence reports are committed, and ScamSniffer's lists are GPL-3.0: they are never committed
// or distributed (AGENTS.md §4). An address or domain that only ScamSniffer lists is written to a
// report as "ss:<16 hex>" (SHA-256 of its lowercase form): counts and joins survive, the entry
// itself is not published. Forta (MIT) and MetaMask (DBAD) entries stay readable.
import { createHash } from "node:crypto";
import { normalizeFeedDomain } from "../src/threat-intel.js";

const SOURCES = {
  ssAddresses: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
  ssDomains: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
  forta: "https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/phishing_scams.csv",
  metamask: "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
};

export type Redaction = { addresses: ReadonlySet<string>; domains: ReadonlySet<string> };

async function text(url: string, fetchImpl: typeof fetch): Promise<string> {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

/** The entries only ScamSniffer lists (fetched at run time, held in memory only). */
export async function scamSnifferOnly(fetchImpl: typeof fetch = fetch): Promise<Redaction> {
  const [ssA, ssD, forta, mm] = await Promise.all([text(SOURCES.ssAddresses, fetchImpl), text(SOURCES.ssDomains, fetchImpl), text(SOURCES.forta, fetchImpl), text(SOURCES.metamask, fetchImpl)]);
  const fortaSet = new Set(
    forta
      .split("\n")
      .slice(1)
      .map((l) => (l.split(",")[0] ?? "").toLowerCase()),
  );
  const addresses = new Set(
    (JSON.parse(ssA) as unknown[])
      .map((a) => String(a).trim().toLowerCase())
      .filter((a) => /^0x[0-9a-f]{40}$/.test(a) && !fortaSet.has(a)),
  );
  const mmSet = new Set(((JSON.parse(mm) as { blacklist?: string[] }).blacklist ?? []).map(normalizeFeedDomain).filter((d): d is string => d !== null));
  const domains = new Set((JSON.parse(ssD) as string[]).map(normalizeFeedDomain).filter((d): d is string => d !== null && !mmSet.has(d)));
  return { addresses, domains };
}

export function ssToken(value: string): string {
  return `ss:${createHash("sha256").update(value.toLowerCase()).digest("hex").slice(0, 16)}`;
}

const ADDRESS = /0x[0-9a-fA-F]{40}/g;
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

function redactString(s: string, r: Redaction, counter: { n: number }): string {
  const a = s.replace(ADDRESS, (m) => (r.addresses.has(m.toLowerCase()) ? (counter.n++, ssToken(m)) : m));
  return a.replace(DOMAIN, (m) => {
    const d = normalizeFeedDomain(m);
    return d && r.domains.has(d) ? (counter.n++, ssToken(d)) : m;
  });
}

/** A deep copy with every ScamSniffer-only address and domain (in values and keys) replaced by its token. */
export function redactScamSniffer<T>(value: T, r: Redaction, counter: { n: number } = { n: 0 }): T {
  if (typeof value === "string") return redactString(value, r, counter) as T;
  if (Array.isArray(value)) return value.map((v) => redactScamSniffer(v, r, counter)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [redactString(k, r, counter), redactScamSniffer(v, r, counter)])) as T;
  }
  return value;
}

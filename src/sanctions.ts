import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "./data/ofac-sdn.js";
import { parseSubject, type Subject } from "./address.js";
import { hash20Of } from "./address-codec.js";

export type SanctionsEvidence = {
  list: "ofac-sdn";
  as_of: string;
  status: "listed" | "not_listed";
  entity?: string;
  ticker?: string;
  /** "same_key": the subject encodes the same 20-byte hash as a listed address in another encoding/chain. */
  match?: "exact" | "same_key";
  listed_address?: string;
};

type Entry = { address: string; ticker: string; name: string };
export type SanctionsRow = readonly [string, string, number, string];
export type SanctionsListMeta = { source: string; publish_date: string; addresses: number; origin: "embedded" | "refreshed" };

type List = { meta: SanctionsListMeta; rows: ReadonlyArray<SanctionsRow>; exact?: Map<string, Entry>; byHash?: Map<string, Entry> };

let current: List = { meta: { source: OFAC_SDN_META.source, publish_date: OFAC_SDN_META.publish_date, addresses: OFAC_SDN_META.addresses, origin: "embedded" }, rows: OFAC_SDN_ADDRESSES };

function indexes(list: List): { exact: Map<string, Entry>; byHash: Map<string, Entry> } {
  if (list.exact && list.byHash) return { exact: list.exact, byHash: list.byHash };
  const exact = new Map<string, Entry>();
  const byHash = new Map<string, Entry>();
  for (const [address, ticker, , name] of list.rows) {
    const entry = { address, ticker, name };
    if (!exact.has(address)) exact.set(address, entry);
    const parsed = parseSubject(address);
    const hash = parsed ? hash20Of(parsed.format, parsed.canonical) : null;
    if (hash && !byHash.has(hash)) byHash.set(hash, entry);
  }
  list.exact = exact;
  list.byHash = byHash;
  return { exact, byHash };
}

/**
 * Swaps in a newer OFAC snapshot fetched at runtime (see deploy/fresh-feeds.ts). The
 * index is built before the swap, so a screen never sees a half-built list.
 */
export function setSanctionsList(rows: ReadonlyArray<SanctionsRow>, meta: Omit<SanctionsListMeta, "origin" | "addresses">): void {
  const next: List = { meta: { ...meta, addresses: rows.length, origin: "refreshed" }, rows };
  indexes(next);
  current = next;
}

export function sanctionsListMeta(): SanctionsListMeta {
  return current.meta;
}

/**
 * Deterministic screen of the subject against the embedded OFAC SDN snapshot:
 * exact match on the canonical address, then on the 20-byte hash it encodes
 * (BCH legacy ↔ cashaddr, BTC P2PKH ↔ P2WPKH, TRX ↔ EVM for the same key).
 * Scope: direct listing only — indirect exposure (funds received from listed
 * addresses) is NOT covered and must not be implied by "not_listed".
 */
export function screenSubject(subject: Subject): SanctionsEvidence {
  const list = current;
  const { exact: ex, byHash: bh } = indexes(list);
  const base = { list: "ofac-sdn" as const, as_of: list.meta.publish_date };
  const hit = ex.get(subject.canonical);
  if (hit) return { ...base, status: "listed", entity: hit.name, ticker: hit.ticker, match: "exact" };
  const hash = hash20Of(subject.format, subject.canonical);
  const keyHit = hash ? bh.get(hash) : undefined;
  if (keyHit) return { ...base, status: "listed", entity: keyHit.name, ticker: keyHit.ticker, match: "same_key", listed_address: keyHit.address };
  return { ...base, status: "not_listed" };
}

/** The embedded snapshot's metadata (the list in use may be newer: sanctionsListMeta()). */
export const SANCTIONS_LIST_META = OFAC_SDN_META;

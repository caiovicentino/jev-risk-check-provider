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

let exact: Map<string, Entry> | null = null;
let byHash: Map<string, Entry> | null = null;

function indexes(): { exact: Map<string, Entry>; byHash: Map<string, Entry> } {
  if (exact && byHash) return { exact, byHash };
  exact = new Map();
  byHash = new Map();
  for (const [address, ticker, , name] of OFAC_SDN_ADDRESSES) {
    const entry = { address, ticker, name };
    if (!exact.has(address)) exact.set(address, entry);
    const parsed = parseSubject(address);
    const hash = parsed ? hash20Of(parsed.format, parsed.canonical) : null;
    if (hash && !byHash.has(hash)) byHash.set(hash, entry);
  }
  return { exact, byHash };
}

/**
 * Deterministic screen of the subject against the embedded OFAC SDN snapshot:
 * exact match on the canonical address, then on the 20-byte hash it encodes
 * (BCH legacy ↔ cashaddr, BTC P2PKH ↔ P2WPKH, TRX ↔ EVM for the same key).
 * Scope: direct listing only — indirect exposure (funds received from listed
 * addresses) is NOT covered and must not be implied by "not_listed".
 */
export function screenSubject(subject: Subject): SanctionsEvidence {
  const { exact: ex, byHash: bh } = indexes();
  const base = { list: "ofac-sdn" as const, as_of: OFAC_SDN_META.publish_date };
  const hit = ex.get(subject.canonical);
  if (hit) return { ...base, status: "listed", entity: hit.name, ticker: hit.ticker, match: "exact" };
  const hash = hash20Of(subject.format, subject.canonical);
  const keyHit = hash ? bh.get(hash) : undefined;
  if (keyHit) return { ...base, status: "listed", entity: keyHit.name, ticker: keyHit.ticker, match: "same_key", listed_address: keyHit.address };
  return { ...base, status: "not_listed" };
}

export const SANCTIONS_LIST_META = OFAC_SDN_META;

import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "./data/ofac-sdn.js";
import type { Subject } from "./address.js";

export type SanctionsEvidence = {
  list: "ofac-sdn";
  as_of: string;
  status: "listed" | "not_listed";
  entity?: string;
  ticker?: string;
};

let index: Map<string, { ticker: string; name: string }> | null = null;

function lookup(): Map<string, { ticker: string; name: string }> {
  if (index) return index;
  index = new Map();
  for (const [address, ticker, , name] of OFAC_SDN_ADDRESSES) {
    if (!index.has(address)) index.set(address, { ticker, name });
  }
  return index;
}

/**
 * Deterministic screen of the subject against the embedded OFAC SDN snapshot.
 * Scope: direct listing of the address only — indirect exposure (funds received
 * from listed addresses) is NOT covered and must not be implied by "not_listed".
 */
export function screenSubject(subject: Subject): SanctionsEvidence {
  const hit = lookup().get(subject.canonical);
  const base = { list: "ofac-sdn" as const, as_of: OFAC_SDN_META.publish_date };
  return hit ? { ...base, status: "listed", entity: hit.name, ticker: hit.ticker } : { ...base, status: "not_listed" };
}

export const SANCTIONS_LIST_META = OFAC_SDN_META;

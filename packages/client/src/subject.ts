// Subject (address) comparison with the provider's canonical rules.
//
// EVM, bech32 and cashaddr are case-insensitive (canonical lowercase; the CAIP-10 prefix and
// `bitcoincash:` are stripped). Base58 (Solana, Tron, BTC legacy) is case-SENSITIVE: a
// case-flipped base58 string is a different address.
import { base58Decode } from "./solana.js";

export type AddressFormat = "evm" | "base58" | "bech32" | "cashaddr";

export interface ParsedSubject {
  /** Address as given, after CAIP-10 prefix removal. */
  address: string;
  /** Canonical comparison form. */
  canonical: string;
  format: AddressFormat;
  /** CAIP-2 chain id when a CAIP-10 account id was given. */
  caip2?: string;
}

const EVM = /^0x[0-9a-fA-F]{40}$/;
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{25,106}$/;
const BECH32 = /^(bc|tb|bcrt|ltc|bnb)1[02-9ac-hj-np-z]{8,87}$/;
const CASHADDR = /^(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}$/;
const CAIP10 = /^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32}):(.+)$/;

/**
 * Parses an address the way the provider does (format level). Checksums are not validated
 * here: the provider validates them before it signs a subject.
 */
/** The CAIP-2 namespaces an address can belong to. */
export type Namespace = "eip155" | "solana" | "tron" | "bip122";

/**
 * The CAIP-2 namespace an address's own format belongs to, as the provider decides it: EVM →
 * eip155, a 32-byte base58 key → solana, TRON (base58, version 0x41) → tron, the UTXO chains'
 * formats → bip122; null for one the API serves under no namespace (an XRP or BNB Beacon address).
 * Checksums stay the provider's to refuse.
 */
export function addressNamespace(subject: Pick<ParsedSubject, "format" | "canonical">): Namespace | null {
  if (subject.format === "evm") return "eip155";
  if (subject.format === "bech32") return /^(bc|tb|bcrt|ltc)1/.test(subject.canonical) ? "bip122" : null;
  if (subject.format === "cashaddr") return "bip122";
  if (subject.canonical.startsWith("r")) return null; // XRP: no UTXO-chain address starts with "r"
  const raw = base58Decode(subject.canonical);
  if (!raw) return null;
  if (raw.length === 32) return "solana";
  if (raw.length === 25 && raw[0] === 0x41) return "tron";
  return raw.length === 25 || raw.length === 26 ? "bip122" : null;
}

export function parseSubject(raw: string): ParsedSubject | null {
  const subject = parseAddress(raw);
  // A CAIP-10 id whose chain cannot hold its address ("solana:…:0x…") names nothing, as for the provider.
  return subject && (!subject.caip2 || addressNamespace(subject) === subject.caip2.slice(0, subject.caip2.indexOf(":"))) ? subject : null;
}

function parseAddress(raw: string): ParsedSubject | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 160 || raw !== raw.trim()) return null;
  let address = raw;
  let caip2: string | undefined;
  const caip = CAIP10.exec(raw);
  if (caip) {
    caip2 = `${caip[1]}:${caip[2]}`;
    address = caip[3] as string;
  }
  const withChain = caip2 ? { caip2 } : {};
  if (EVM.test(address)) return { address, canonical: address.toLowerCase(), format: "evm", ...withChain };
  // bech32 and cashaddr are case-insensitive but never mixed-case.
  const lower = address.toLowerCase();
  const singleCase = address === lower || address === address.toUpperCase();
  if (singleCase && BECH32.test(lower)) return { address, canonical: lower, format: "bech32", ...withChain };
  if (singleCase && CASHADDR.test(lower)) {
    return { address, canonical: lower.replace(/^bitcoincash:/, ""), format: "cashaddr", ...withChain };
  }
  // A mixed-case bech32 or cashaddr string is invalid, not a "base58" address that no list contains;
  // TRON's hex form ("41" + 20 bytes) is not screened by its base58 listing: both are rejected (as the provider does).
  if (BECH32.test(lower) || CASHADDR.test(lower) || /^41[0-9a-fA-F]{40}$/.test(address)) return null;
  if (BASE58.test(address)) return { address, canonical: address, format: "base58", ...withChain };
  return null;
}

/**
 * Whether two address strings denote the same subject. False when either is not an address.
 *
 * @example
 * sameSubject("0xAbC…", "eip155:8453:0xabc…")   // true  (EVM: case-insensitive, CAIP-10 stripped)
 * sameSubject("9WzDX…AWWM", "9wzdx…awwm")        // false (base58: case-sensitive)
 */
export function sameSubject(a: string, b: string): boolean {
  const x = parseSubject(a);
  const y = parseSubject(b);
  // The same EVM key is one subject on every eip155 chain; across namespaces it is not.
  const ns = (caip2: string) => caip2.slice(0, caip2.indexOf(":"));
  return x !== null && y !== null && x.canonical === y.canonical && (!x.caip2 || !y.caip2 || ns(x.caip2) === ns(y.caip2));
}

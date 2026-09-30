// Subject (address) comparison with the provider's canonical rules.
//
// EVM, bech32 and cashaddr are case-insensitive (canonical lowercase; the CAIP-10 prefix and
// `bitcoincash:` are stripped). Base58 (Solana, Tron, BTC legacy) is case-SENSITIVE: a
// case-flipped base58 string is a different address.

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
export function parseSubject(raw: string): ParsedSubject | null {
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
  return x !== null && y !== null && x.canonical === y.canonical;
}

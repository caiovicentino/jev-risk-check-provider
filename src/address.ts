import { base58Check, cashaddrHash20 } from "./address-codec.js";

// Subject address parsing. The wallet is the only field every verdict is keyed on,
// so it must be an address and nothing else: no prose, no padding, no unicode.
export type AddressFormat = "evm" | "base58" | "bech32" | "cashaddr";

export type Subject = {
  /** Address as submitted (after CAIP-10 prefix removal). */
  address: string;
  /** Canonical form used for list lookups (EVM + bech32 lowercased). */
  canonical: string;
  format: AddressFormat;
  /** CAIP-2 chain id when the caller used a CAIP-10 account id. */
  caip2?: string;
};

const EVM = /^0x[0-9a-fA-F]{40}$/;
// Bitcoin-style base58 alphabet (Solana, Tron, BTC legacy, LTC, DOGE, DASH, ZEC t-addr, XRP, XMR).
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{25,106}$/;
const BECH32 = /^(bc|tb|bcrt|ltc|bnb)1[02-9ac-hj-np-z]{8,87}$/;
const CASHADDR = /^(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}$/;
const CAIP10 = /^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32}):(.+)$/;

export function parseSubject(raw: string): Subject | null {
  if (raw.length === 0 || raw.length > 160 || raw !== raw.trim()) return null;
  let address = raw;
  let caip2: string | undefined;
  const caip = raw.match(CAIP10);
  if (caip) {
    caip2 = `${caip[1]}:${caip[2]}`;
    address = caip[3] as string;
  }
  if (EVM.test(address)) return { address, canonical: address.toLowerCase(), format: "evm", ...(caip2 ? { caip2 } : {}) };
  // bech32 is case-insensitive but never mixed-case.
  const lower = address.toLowerCase();
  if ((address === lower || address === address.toUpperCase()) && BECH32.test(lower)) {
    return { address, canonical: lower, format: "bech32", ...(caip2 ? { caip2 } : {}) };
  }
  if ((address === lower || address === address.toUpperCase()) && CASHADDR.test(lower)) {
    // Checksum must verify: a corrupted cashaddr is a different (unowned) address.
    if (!cashaddrHash20(lower)) return null;
    return { address, canonical: lower.replace(/^bitcoincash:/, ""), format: "cashaddr", ...(caip2 ? { caip2 } : {}) };
  }
  if (BASE58.test(address)) {
    // Base58Check formats (BTC/LTC/DOGE/DASH/BCH legacy/TRX/ZEC t-addr) must carry a
    // valid checksum, so a case-flipped variant of a listed address is rejected
    // instead of being screened as a "different", unlisted address.
    const check = base58Check(address);
    if (check.checksummed && !check.valid) return null;
    return { address, canonical: address, format: "base58", ...(caip2 ? { caip2 } : {}) };
  }
  return null;
}

/**
 * Whether two address strings denote the same subject. EVM, bech32 and cashaddr
 * compare case-insensitively (via their canonical form); base58 (Solana, Tron, BTC
 * legacy) is case-SENSITIVE: a case-flipped base58 string is a different address.
 */
export function sameSubject(a: string, b: string): boolean {
  const x = parseSubject(a);
  const y = parseSubject(b);
  return !!x && !!y && x.canonical === y.canonical;
}

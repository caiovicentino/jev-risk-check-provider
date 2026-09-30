import { createHash } from "node:crypto";

// Checksummed address encodings. Used to (1) reject case-flipped or corrupted
// variants of checksummed formats and (2) screen an address by the 20-byte hash
// it encodes, so one key cannot dodge a sanctions listing by switching encoding
// (BCH legacy ↔ cashaddr, BTC P2PKH ↔ P2WPKH, TRX ↔ EVM for the same key).

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX = new Map([...B58].map((c, i) => [c, i]));
// The XRP Ledger's base58 alphabet ("r" is its zero digit): classic addresses are Base58Check in it.
const XRP_B58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const XRP_INDEX = new Map([...XRP_B58].map((c, i) => [c, i]));

export function base58Decode(input: string, alphabet: { index: Map<string, number>; zero: string } = { index: B58_INDEX, zero: "1" }): Uint8Array | null {
  if (input.length === 0 || input.length > 120) return null;
  let value = 0n;
  for (const ch of input) {
    const digit = alphabet.index.get(ch);
    if (digit === undefined) return null;
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  for (const ch of input) {
    if (ch !== alphabet.zero) break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

function sha256d(data: Uint8Array): Uint8Array {
  return createHash("sha256").update(createHash("sha256").update(data).digest()).digest();
}

export type Base58CheckResult = { checksummed: boolean; valid: boolean; hash20?: string };

/**
 * Base58Check (BTC/LTC/DOGE/DASH/BCH-legacy/TRX: 1-byte version + 20-byte hash;
 * ZEC t-addr: 2-byte version). Other decoded lengths (e.g. 32-byte Solana keys)
 * carry no checksum and are reported as not checksummed.
 */
export function base58Check(input: string): Base58CheckResult {
  const result = checkedDecode(base58Decode(input));
  // An XRP classic address ("r…", 25 bytes in the XRP alphabet) fails the Bitcoin-alphabet checksum:
  // it is valid when it verifies in its own alphabet.
  if (result.checksummed && !result.valid && input.startsWith("r")) {
    const xrp = checkedDecode(base58Decode(input, { index: XRP_INDEX, zero: "r" }));
    if (xrp.checksummed && xrp.valid) return xrp;
  }
  return result;
}

function checkedDecode(raw: Uint8Array | null): Base58CheckResult {
  if (!raw) return { checksummed: false, valid: false };
  if (raw.length !== 25 && raw.length !== 26) return { checksummed: false, valid: true };
  const body = raw.subarray(0, raw.length - 4);
  const sum = sha256d(body).subarray(0, 4);
  const valid = sum.every((b, i) => b === raw[raw.length - 4 + i]);
  const hash = body.subarray(body.length - 20);
  return { checksummed: true, valid, ...(valid ? { hash20: Buffer.from(hash).toString("hex") } : {}) };
}

// --- bech32 (BIP-173) and cashaddr (BCH) --------------------------------------
const B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const B32_INDEX = new Map([...B32].map((c, i) => [c, i]));

function convertBits(data: number[], from: number, to: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from !== 0) return null;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    return null;
  }
  return out;
}

function bech32Polymod(values: number[]): number {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= gen[i] as number;
  }
  return chk >>> 0;
}

/** Witness v0, 20-byte program (P2WPKH/LTC equivalent): returns the hash160 hex. */
export function bech32Hash20(address: string): string | null {
  const lower = address.toLowerCase();
  const sep = lower.lastIndexOf("1");
  if (sep < 1 || lower.length - sep - 1 < 7) return null;
  const hrp = lower.slice(0, sep);
  const data: number[] = [];
  for (const ch of lower.slice(sep + 1)) {
    const v = B32_INDEX.get(ch);
    if (v === undefined) return null;
    data.push(v);
  }
  const expanded = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  if (bech32Polymod([...expanded, ...data]) !== 1) return null; // bech32 (v0) constant
  const words = data.slice(0, -6);
  if (words[0] !== 0) return null;
  const program = convertBits(words.slice(1), 5, 8, false);
  return program && program.length === 20 ? Buffer.from(program).toString("hex") : null;
}

function cashaddrPolymod(values: number[]): bigint {
  const gen = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= gen[i] as bigint;
  }
  return c ^ 1n;
}

/** BCH cashaddr with a 160-bit hash (with or without the bitcoincash: prefix). */
export function cashaddrHash20(address: string): string | null {
  const lower = address.toLowerCase();
  const payload = lower.startsWith("bitcoincash:") ? lower.slice("bitcoincash:".length) : lower;
  const data: number[] = [];
  for (const ch of payload) {
    const v = B32_INDEX.get(ch);
    if (v === undefined) return null;
    data.push(v);
  }
  const prefix = [..."bitcoincash"].map((c) => c.charCodeAt(0) & 31);
  if (cashaddrPolymod([...prefix, 0, ...data]) !== 0n) return null;
  const bytes = convertBits(data.slice(0, -8), 5, 8, false);
  if (!bytes || bytes.length !== 21 || ((bytes[0] as number) & 0x07) !== 0) return null; // size bits 0 = 160-bit hash
  return Buffer.from(bytes.slice(1)).toString("hex");
}

/** The 20-byte hash an address encodes, when its format carries one. */
export function hash20Of(format: "evm" | "base58" | "bech32" | "cashaddr", canonical: string): string | null {
  if (format === "evm") return canonical.slice(2);
  if (format === "base58") return base58Check(canonical).hash20 ?? null;
  if (format === "bech32") return bech32Hash20(canonical);
  return cashaddrHash20(canonical);
}

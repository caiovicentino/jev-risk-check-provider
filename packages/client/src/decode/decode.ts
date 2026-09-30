// Vendored from snap/src/decode.ts by scripts/sync-decoders.mjs. Edit the Snap source and re-sync.
/**
 * Public decoding API of the x402check Snap.
 *
 * Pure functions only (no Snap globals, no network). Each decoder maps a raw
 * wallet request to the address(es) that should be risk-checked and a short
 * human-readable summary:
 * - transactions: tx.ts (calldata, wrappers, payable calls);
 * - EIP-712 typed data: eip712.ts (canonicalization mirroring what MetaMask
 *   signs) + typed.ts (permits, Permit2, orders, SafeTx, generic);
 * - personal_sign: personal.ts.
 */
import { decodePersonalSign } from "./personal.js";
import { decodeTypedData } from "./typed.js";
import type { Decoded } from "./util.js";
import { isRecord } from "./util.js";

export * from "./util.js";
export { canonicalizeTypedData } from "./eip712.js";
export type { Canonical, CanonStruct, CanonValue } from "./eip712.js";
export { decodeCallAction, decodeTransaction, lenientAddress, normalizeCalldata } from "./tx.js";
export type { TransactionLike } from "./tx.js";
export { decodeTypedData, isOrderType } from "./typed.js";
export { decodePersonalSign, isMostlyPrintable } from "./personal.js";

export type SignatureLike = { from?: unknown; data?: unknown; signatureMethod?: unknown };

function looksLikeJson(data: string): boolean {
  const start = data.slice(0, 16).trimStart();
  return start.startsWith("{") || start.startsWith("[");
}

/**
 * Routes a signature request to the right decoder by method (or by data shape
 * when the method is missing).
 *
 * @param signature - The signature request.
 * @param originHostname - Hostname of the requesting site, if known.
 * @returns The decoded request.
 */
export function decodeSignature(signature: SignatureLike, originHostname?: string): Decoded {
  const method = typeof signature.signatureMethod === "string" ? signature.signatureMethod : "";
  const { data, from } = signature;
  switch (method) {
    case "personal_sign":
      return decodePersonalSign(data, from, originHostname);
    case "eth_signTypedData":
    case "eth_signTypedData_v1":
      return decodeTypedData(data, from, "eth_signTypedData v1");
    case "eth_signTypedData_v3":
      return decodeTypedData(data, from, "eth_signTypedData_v3");
    case "eth_signTypedData_v4":
      return decodeTypedData(data, from, "eth_signTypedData_v4");
    default:
      if (Array.isArray(data) || isRecord(data)) return decodeTypedData(data, from, method || "typed data");
      if (typeof data === "string" && looksLikeJson(data)) return decodeTypedData(data, from, method || "typed data");
      return decodePersonalSign(data, from, originHostname);
  }
}

// Addresses a community list must never flag. A poisoned or mistaken upstream entry for one of
// these would block payments to x402check itself or to the assets every check deals in (a
// `known_scam_address` hit blocks at any tier), and a listed token contract would also seed a
// code fingerprint matching every contract that shares its logic. Feed builders drop them before
// hashing (deploy/scamsniffer-refresh.ts, scripts/update-threat-feeds.ts).
import { DEFAULT_ASSETS } from "@x402/evm";
import { knownValueTokens } from "./simulation.js";

/** x402check's own EVM pay_to (deploy/wrangler.toml PAY_TO_EVM; the SDK's X402CHECK_PAY_TO). */
export const X402CHECK_PAY_TO_EVM = "0xbf88b1f49b5e8ec386289341c4a5ee00bb0e0178";
/** The canonical Permit2 contract, at the same address on every EVM chain. */
export const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
/** x402's Permit2 proxies (exact, upto): the SDK's X402_PERMIT2_PROXIES. */
export const X402_PERMIT2_PROXIES = ["0x402085c248eea27d92e8b30b2c58ed07f9e20001", "0x4020a4f3b7b90cca423b9fabcc0ce57c6c240002"] as const;

/** The asset x402 charges in on each EVM network (USDC on most): the x402 SDK's default assets. */
export function x402DefaultAssets(): string[] {
  return Object.values(DEFAULT_ASSETS).flatMap((assets) => assets.map((a) => a.asset.toLowerCase()));
}

/**
 * Lowercase EVM addresses never added to a community address set: our pay_to, Permit2 and x402's
 * proxies, the asset x402 pays in per network, and the major tokens the simulator values.
 */
export const NEVER_FLAG_EVM: ReadonlySet<string> = new Set([X402CHECK_PAY_TO_EVM, PERMIT2, ...X402_PERMIT2_PROXIES, ...x402DefaultAssets(), ...knownValueTokens()]);

/** Whether a feed's EVM address must be dropped (case-insensitive); `extra` holds lowercase addresses. */
export function neverFlag(address: string, extra?: ReadonlySet<string>): boolean {
  const a = address.toLowerCase();
  return NEVER_FLAG_EVM.has(a) || (extra?.has(a) ?? false);
}

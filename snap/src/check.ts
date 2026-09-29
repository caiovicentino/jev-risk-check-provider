/**
 * The insight pipeline behind `onTransaction` and `onSignature`.
 *
 * Decoding is always local. What happens next depends on the mode:
 * - `paidChecks: false` (this version, see src/config.ts): nothing is sent
 *   anywhere, and the local result is shown as NOT verified by x402check;
 * - `paidChecks: true`: the counterparties are risk-checked with x402check and
 *   the verdict (with its simulation evidence) is rendered.
 *
 * The mode is a parameter, so tests can exercise the paid mode while the
 * shipped constant stays false.
 */
import type {
  Component,
  OnSignatureHandler,
  OnSignatureResponse,
  OnTransactionHandler,
  OnTransactionResponse,
} from "@metamask/snaps-sdk";

import type { Decoded } from "./decode";
import { decodeSignature, decodeTransaction } from "./decode";
import type { FetchLike } from "./request";
import { buildRiskCheckBodies, originHost, postRiskChecks } from "./request";
import type { InsightResult, RequestKind } from "./ui";
import { renderLocalOnly, renderOutcome, renderUnpaid, withFallback } from "./ui";

export type CheckMode = {
  /** Whether x402check is called at all (PAID_CHECKS_SUPPORTED in the Snap). */
  paidChecks: boolean;
  /** The network transport. Never called unless `paidChecks` is true. */
  fetchImpl: FetchLike;
};

/**
 * Produces the insight for one decoded request.
 *
 * @param decoded - The locally decoded request.
 * @param origin - The requesting origin.
 * @param kind - Transaction or signature.
 * @param mode - Paid checks on or off, and the transport.
 * @returns The insight.
 */
export async function runCheck(decoded: Decoded, origin: string | undefined, kind: RequestKind, mode: CheckMode): Promise<InsightResult> {
  const host = originHost(origin);
  if (!mode.paidChecks) {
    // Checks are paid per call (x402) and this version cannot pay: send nothing.
    return renderUnpaid(decoded, host, kind);
  }
  const bodies = buildRiskCheckBodies(decoded, origin);
  if (bodies.length === 0) {
    // Nothing to check (e.g. contract deployment): no network request at all.
    return renderLocalOnly(decoded, host);
  }
  // No client or install identifier is sent: checks are paid per call (x402).
  const outcome = await postRiskChecks(bodies, mode.fetchImpl);
  return renderOutcome(decoded, outcome, kind, host);
}

/**
 * The Snap's insight handlers for a given mode. They never throw: any
 * unexpected error becomes the critical "check failed" insight.
 *
 * @param mode - Paid checks on or off, and the transport.
 * @returns The `onTransaction` and `onSignature` handlers.
 */
export function insightHandlers(mode: CheckMode): { onTransaction: OnTransactionHandler; onSignature: OnSignatureHandler } {
  const onTransaction: OnTransactionHandler = async ({ transaction, chainId, transactionOrigin }) => {
    const result = await withFallback("transaction", async () =>
      runCheck(decodeTransaction(transaction, chainId), transactionOrigin, "transaction", mode),
    );
    const response: OnTransactionResponse = result.severity
      ? { content: result.content, severity: result.severity }
      : { content: result.content };
    return response;
  };

  const onSignature: OnSignatureHandler = async ({ signature, signatureOrigin }) => {
    const result = await withFallback("signature", async () =>
      runCheck(decodeSignature(signature, originHost(signatureOrigin)), signatureOrigin, "signature", mode),
    );
    // snaps-sdk 8.x types `OnSignatureResponse.content` as the legacy `Component`,
    // but the runtime validates it with the same struct as transaction insights,
    // which accepts JSX elements.
    const content = result.content as unknown as Component;
    const response: OnSignatureResponse = result.severity ? { content, severity: result.severity } : { content };
    return response;
  };

  return { onTransaction, onSignature };
}

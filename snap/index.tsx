/**
 * x402check MetaMask Snap.
 *
 * Decodes every transaction and signature locally, risk-checks the real
 * counterparty (recipient / spender / operator / contract) with x402check
 * before the user signs, and renders the signed verdict.
 *
 * Runtime: only the `snap` and `ethereum` globals exist in the Snap sandbox
 * (plus the granted endowments such as `fetch`), so every Snap API call goes
 * through `snap.request(...)`.
 */
import type {
  Component,
  OnInstallHandler,
  OnSignatureHandler,
  OnSignatureResponse,
  OnTransactionHandler,
  OnTransactionResponse,
  OnUpdateHandler,
} from "@metamask/snaps-sdk";

import type { Decoded } from "./src/decode";
import { decodeSignature, decodeTransaction } from "./src/decode";
import { buildRiskCheckBody, originHost, postRiskCheck } from "./src/request";
import { clearLegacyState, getInstallIdSafe, isDisclosureShown, markDisclosureShown } from "./src/state";
import type { InsightResult, RequestKind } from "./src/ui";
import { disclosureContent, renderLocalOnly, renderOutcome } from "./src/ui";

async function runCheck(decoded: Decoded, origin: string | undefined, kind: RequestKind): Promise<InsightResult> {
  const host = originHost(origin);
  const body = buildRiskCheckBody(decoded, origin);
  if (!body) {
    // Nothing to check (e.g. contract deployment): no network request at all.
    return renderLocalOnly(decoded, host);
  }
  const installId = await getInstallIdSafe();
  const outcome = await postRiskCheck(body, installId, async (input, init) => fetch(input, init));
  return renderOutcome(decoded, outcome, kind, host);
}

async function showDisclosure(): Promise<void> {
  await snap.request({
    method: "snap_dialog",
    params: { type: "alert", content: disclosureContent() },
  });
  try {
    await markDisclosureShown();
  } catch {
    // Not persisted: it is simply shown again on the next update.
  }
}

export const onTransaction: OnTransactionHandler = async ({ transaction, chainId, transactionOrigin }) => {
  const decoded = decodeTransaction(transaction, chainId);
  const result = await runCheck(decoded, transactionOrigin, "transaction");
  const response: OnTransactionResponse = result.severity
    ? { content: result.content, severity: result.severity }
    : { content: result.content };
  return response;
};

export const onSignature: OnSignatureHandler = async ({ signature, signatureOrigin }) => {
  const decoded = decodeSignature(signature, originHost(signatureOrigin));
  const result = await runCheck(decoded, signatureOrigin, "signature");
  // snaps-sdk 8.x types `OnSignatureResponse.content` as the legacy `Component`,
  // but the runtime validates it with the same struct as transaction insights,
  // which accepts JSX elements.
  const content = result.content as unknown as Component;
  const response: OnSignatureResponse = result.severity
    ? { content, severity: result.severity }
    : { content };
  return response;
};

export const onInstall: OnInstallHandler = async () => {
  // Creates and persists the random install id; never blocks the disclosure.
  await getInstallIdSafe();
  await showDisclosure();
  return null;
};

export const onUpdate: OnUpdateHandler = async () => {
  // 0.1.x stored an SRP-derived id in the encrypted state; drop it.
  try {
    await clearLegacyState();
  } catch {
    // Best effort: the random install id below supersedes it either way.
  }
  await getInstallIdSafe();
  let shown = false;
  try {
    shown = await isDisclosureShown();
  } catch {
    shown = false;
  }
  if (!shown) {
    await showDisclosure();
  }
  return null;
};

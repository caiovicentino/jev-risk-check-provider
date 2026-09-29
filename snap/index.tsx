/**
 * x402check MetaMask Snap.
 *
 * Decodes every transaction and signature locally and shows who really
 * receives your funds or permissions (recipient / spender / operator /
 * contract), with the dangers it can prove locally, before you sign.
 *
 * Risk checks with x402check are paid per call (x402) and this version cannot
 * pay yet, so it sends nothing (PAID_CHECKS_SUPPORTED in src/config.ts). The
 * paid pipeline in src/check.ts is kept for when it can.
 *
 * Runtime: only the `snap` and `ethereum` globals exist in the Snap sandbox
 * (plus the endowments granted by the manifest), so every Snap API call goes
 * through `snap.request(...)`.
 */
import type { OnInstallHandler, OnSignatureHandler, OnTransactionHandler, OnUpdateHandler } from "@metamask/snaps-sdk";

import { insightHandlers } from "./src/check";
import { PAID_CHECKS_SUPPORTED } from "./src/config";
import { clearLegacyState, forgetInstallId, isDisclosureShown, markDisclosureShown } from "./src/state";
import { disclosureContent } from "./src/ui";

const insights = insightHandlers({
  paidChecks: PAID_CHECKS_SUPPORTED,
  // Only ever called in paid mode. While PAID_CHECKS_SUPPORTED is false the
  // manifest grants no network access, so `fetch` does not even exist here.
  fetchImpl: async (input, init) => fetch(input, init),
});

export const onTransaction: OnTransactionHandler = insights.onTransaction;

export const onSignature: OnSignatureHandler = insights.onSignature;

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

export const onInstall: OnInstallHandler = async () => {
  await showDisclosure();
  return null;
};

export const onUpdate: OnUpdateHandler = async () => {
  // Earlier versions stored an identifier that is no longer used or sent:
  // 0.1.x an SRP-derived client id (encrypted state), 0.2-0.3 a random install
  // id (unencrypted state). Delete both; best effort, never blocks the update.
  try {
    await clearLegacyState();
  } catch {
    // Ignored: nothing reads it any more.
  }
  try {
    await forgetInstallId();
  } catch {
    // Ignored: nothing reads it, and markDisclosureShown drops it as well.
  }
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

/**
 * Per-install state, persisted with `snap_manageState` in the unencrypted
 * state (nothing in it is secret, and it is readable while the wallet is
 * locked).
 *
 * The only thing stored is which version of the privacy disclosure was shown.
 * The Snap keeps and sends no identifier (every x402check evaluation is paid
 * per call via x402). Identifiers stored by earlier versions are deleted on
 * update: the random install id of 0.2-0.3 (this state, see `forgetInstallId`)
 * and the SRP-derived client id of 0.1.x (the encrypted state, see
 * `clearLegacyState`).
 */
import type { Json } from "@metamask/snaps-sdk";

import { PAID_CHECKS_SUPPORTED } from "./config";

/**
 * Bump whenever the disclosure changes, so updated installs see it again.
 * 1: v0.2 (counterparty, chain, site, summary). 2: v0.3 adds the full
 * transaction sent for simulation (public RPC, Blockscout). 3: local only:
 * nothing is sent, because checks are paid per call (x402) and this version
 * cannot pay. 4: reserved for the paid-mode disclosure, so turning
 * PAID_CHECKS_SUPPORTED on shows every install what is sent before it is.
 */
export const DISCLOSURE_VERSION = PAID_CHECKS_SUPPORTED ? 4 : 3;

/** Keys written by earlier versions that nothing reads any more. */
const OBSOLETE_KEYS = new Set(["installId"]);

type State = Record<string, Json>;

async function readState(): Promise<State> {
  const state = await snap.request({
    method: "snap_manageState",
    params: { operation: "get", encrypted: false },
  });
  return state ?? {};
}

async function writeState(newState: State): Promise<void> {
  await snap.request({
    method: "snap_manageState",
    params: { operation: "update", encrypted: false, newState },
  });
}

function withoutObsoleteKeys(state: State): State {
  return Object.fromEntries(Object.entries(state).filter(([key]) => !OBSOLETE_KEYS.has(key)));
}

/**
 * Whether the current privacy disclosure was already shown.
 *
 * @returns True when shown.
 */
export async function isDisclosureShown(): Promise<boolean> {
  const state = await readState();
  return state.disclosureVersion === DISCLOSURE_VERSION;
}

/** Records that the current privacy disclosure was shown (and drops obsolete keys). */
export async function markDisclosureShown(): Promise<void> {
  const state = await readState();
  await writeState({ ...withoutObsoleteKeys(state), disclosureVersion: DISCLOSURE_VERSION });
}

/**
 * Deletes the random install id that 0.2-0.3 stored and sent with every
 * request (for a free tier that no longer exists). Nothing sends or reads it
 * any more. Other keys (the disclosure version) are preserved.
 *
 * @returns Whether an install id was found and deleted.
 */
export async function forgetInstallId(): Promise<boolean> {
  const state = await readState();
  const next = withoutObsoleteKeys(state);
  if (Object.keys(next).length === Object.keys(state).length) return false;
  await writeState(next);
  return true;
}

/**
 * Deletes state written by 0.1.x, which kept an SRP-derived client id in the
 * (default, encrypted) Snap state.
 *
 * @returns Whether legacy state was found and cleared.
 */
export async function clearLegacyState(): Promise<boolean> {
  const legacy = await snap.request({ method: "snap_manageState", params: { operation: "get" } });
  if (!legacy || !("clientId" in legacy)) return false;
  await snap.request({ method: "snap_manageState", params: { operation: "clear" } });
  return true;
}

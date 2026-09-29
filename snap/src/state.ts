/**
 * Per-install state, persisted with `snap_manageState`.
 *
 * The install id is RANDOM (16 bytes from `crypto.getRandomValues`). It is never
 * derived from the Secret Recovery Phrase, so it cannot be linked to the user's
 * keys or accounts, and it resets when the Snap is reinstalled. It is used only
 * to count the free daily checks on the server.
 *
 * The id is not a secret (it is sent with every request), so it lives in the
 * unencrypted Snap state: faster to read and available while locked.
 */
import type { Json } from "@metamask/snaps-sdk";

export const DISCLOSURE_VERSION = 1;
const INSTALL_ID_RE = /^[0-9a-f]{32}$/u;

type State = Record<string, Json>;

/**
 * Generates a random 16-byte install id as 32 lowercase hex characters.
 *
 * @returns The install id.
 */
export function randomInstallId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

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

let cachedInstallId: string | undefined;

/**
 * Returns the persisted install id, creating and persisting one if missing.
 *
 * @returns The install id.
 */
export async function getInstallId(): Promise<string> {
  if (cachedInstallId) return cachedInstallId;
  const state = await readState();
  const existing = state.installId;
  if (typeof existing === "string" && INSTALL_ID_RE.test(existing)) {
    cachedInstallId = existing;
    return existing;
  }
  const installId = randomInstallId();
  await writeState({ ...state, installId });
  cachedInstallId = installId;
  return installId;
}

/**
 * Like {@link getInstallId}, but never throws: if the state is unavailable an
 * ephemeral random id is used for this execution.
 *
 * @returns The install id.
 */
export async function getInstallIdSafe(): Promise<string> {
  try {
    return await getInstallId();
  } catch {
    cachedInstallId = cachedInstallId ?? randomInstallId();
    return cachedInstallId;
  }
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

/** Records that the current privacy disclosure was shown. */
export async function markDisclosureShown(): Promise<void> {
  const state = await readState();
  await writeState({ ...state, disclosureVersion: DISCLOSURE_VERSION });
}

/**
 * Deletes state written by 0.1.x, which kept an SRP-derived client id in the
 * (default, encrypted) Snap state. The random install id replaces it.
 *
 * @returns Whether legacy state was found and cleared.
 */
export async function clearLegacyState(): Promise<boolean> {
  const legacy = await snap.request({ method: "snap_manageState", params: { operation: "get" } });
  if (!legacy || !("clientId" in legacy)) return false;
  await snap.request({ method: "snap_manageState", params: { operation: "clear" } });
  return true;
}

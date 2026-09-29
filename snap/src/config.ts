/**
 * The single switch for x402check's paid risk checks.
 *
 * Every x402check evaluation is paid per call via x402 (there is no free tier),
 * and this version of the Snap cannot pay yet. So it sends NOTHING anywhere:
 * every transaction and signature is decoded and rendered locally, marked
 * "NOT verified by x402check", and never shown as an all-clear. The request,
 * verdict and simulation code is kept, and tested, for the paid mode.
 *
 * To turn paid checks on, once the Snap can pay:
 * 1. set this to `true`;
 * 2. restore `"endowment:network-access": {}` in the `initialPermissions` of
 *    snap.manifest.json. It is removed for least privilege while this is
 *    false, so the Snap has no `fetch` at all (test/snap.test.ts fails while
 *    this flag and the manifest disagree);
 * 3. say how checks are paid in the paid-mode disclosure (`disclosureContent`
 *    in src/ui.tsx). DISCLOSURE_VERSION follows this flag, so every install is
 *    shown the paid-mode disclosure once.
 */
export const PAID_CHECKS_SUPPORTED: boolean = false;

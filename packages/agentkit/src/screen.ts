import {
  createClient,
  interpret,
  verifyAttestation,
  MAX_BATCH,
  X402CHECK_KEY_THUMBPRINTS,
  type Action,
  type FetchLike,
  type Interpretation,
  type RiskCheckRequest,
  type RiskCheckResult,
  type RiskTier,
  type X402CheckClient,
} from "@x402check/client";

const DEFAULT_ISSUER = "did:web:x402check.xyz";
/** An attestation older than this is not accepted (the provider signs at check time). */
const MAX_AGE_SECONDS = 300;
const SEVERITY: Record<Action, number> = { allow: 0, warn: 1, block: 2, not_verified: 3 };

/** How x402check is reached and paid. Pass a credit token or a paying fetch: every check is paid. */
export interface X402checkOptions {
  /** An x402check client. Default: one built from the options below. */
  client?: X402CheckClient | undefined;
  /** Prepaid credit token (x402c_…): $0.001 a check. Buy one with `createClient().buyCredits`. */
  creditToken?: string | undefined;
  /** Fetch for the API and the issuer's DID document: an x402-paying fetch pays per call. Pass a stable reference. */
  fetch?: FetchLike | undefined;
  baseUrl?: string | undefined;
  /** Per API call. Default 10000 ms: a slow check fails closed. */
  timeoutMs?: number | undefined;
  /** The attestation issuer trusted. Default "did:web:x402check.xyz". */
  issuer?: string | undefined;
  /** RFC 7638 thumbprints of the keys accepted. Default: x402check's pinned keys. `false` disables pinning (tests against a local issuer). */
  pinnedKeys?: readonly string[] | false | undefined;
}

/** One counterparty's verdict. */
export interface ScreenedCheck {
  request: RiskCheckRequest;
  interpretation: Interpretation;
  /** The signed attestation, when the API returned one (keep it as evidence). */
  jws?: string | undefined;
}

/** The combined verdict: the worst check decides. */
export interface Screening {
  /** allow · warn (ask a human) · block · not_verified (the check did not complete or cannot be trusted: stop). */
  action: Action;
  /** Most important first. */
  reasons: string[];
  tier?: RiskTier | undefined;
  checks: ScreenedCheck[];
}

export type Screener = (requests: readonly RiskCheckRequest[], signal?: AbortSignal) => Promise<Screening>;

/** Checks, verifies each attestation against the request it answers, and applies the fail-closed policy. */
export function createScreener(options: X402checkOptions = {}): Screener {
  const client =
    options.client ??
    createClient({ baseUrl: options.baseUrl, fetch: options.fetch, timeoutMs: options.timeoutMs ?? 10_000, creditToken: options.creditToken });
  const issuer = options.issuer ?? DEFAULT_ISSUER;
  const pinnedKeys = options.pinnedKeys === false ? undefined : (options.pinnedKeys ?? (issuer === DEFAULT_ISSUER ? X402CHECK_KEY_THUMBPRINTS : undefined));

  return async (requests, signal) => {
    if (requests.length === 0) throw new TypeError("nothing to screen");
    let results: RiskCheckResult[];
    try {
      if (requests.length === 1) {
        results = [await client.check(requests[0] as RiskCheckRequest, { signal })];
      } else {
        const batches: RiskCheckRequest[][] = [];
        for (let i = 0; i < requests.length; i += MAX_BATCH) batches.push(requests.slice(i, i + MAX_BATCH));
        results = (await Promise.all(batches.map((batch) => client.checkBatch(batch, { signal })))).flat();
      }
    } catch (err) {
      const interpretation = interpret(err);
      return { action: "not_verified", reasons: interpretation.reasons, checks: requests.map((request) => ({ request, interpretation })) };
    }
    const checks = await Promise.all(
      requests.map(async (request, i): Promise<ScreenedCheck> => {
        const result = results[i];
        const verification = await verifyAttestation(result?.jws, { issuer, request, maxAgeSeconds: MAX_AGE_SECONDS, fetch: options.fetch, pinnedKeys });
        return { request, interpretation: interpret(result, { verification }), ...(result?.jws ? { jws: result.jws } : {}) };
      }),
    );
    const worst = checks.reduce((w, c) => (SEVERITY[c.interpretation.action] > SEVERITY[w.interpretation.action] ? c : w));
    const reasons = [...worst.interpretation.reasons, ...checks.filter((c) => c !== worst && c.interpretation.action !== "allow").flatMap((c) => c.interpretation.reasons)];
    return { action: worst.interpretation.action, reasons, ...(worst.interpretation.tier ? { tier: worst.interpretation.tier } : {}), checks };
  };
}

// x402check as a provider for the x402 trust-provider extension (x402-foundation/x402#2300). A
// seller's `onBeforeSettle` asks: should I settle this payment from this payer? x402check screens
// the payer's wallet (the OFAC SDN list, phishing and drainer lists, its own watch of drainer
// infrastructure) and answers PASS / FAIL / UNCERTAIN from its signed verdict, after verifying
// the attestation, its key and its binding to the request.
//
// The extension is a proposal: these types mirror its draft (x402-trust-query-v0.1 and
// x402-trust-evaluation-v0.1) and will follow its schema as it settles.
import { createClient, type ClientOptions, type X402CheckClient } from "./client.js";
import { HARD_BLOCK, interpret } from "./interpret.js";
import { X402CHECK_KEY_THUMBPRINTS } from "./keys.js";
import { toCaip2 } from "./normalize.js";
import type { RiskCheckRequest } from "./types.js";
import { verifyAttestation } from "./verify.js";

export type TrustDecision = "PASS" | "FAIL" | "UNCERTAIN";

export interface TrustQuery {
  schema: "x402-trust-query-v0.1";
  payer: { wallet?: string; agent_id?: string; session_id?: string };
  resource: { url: string; method?: string; amount?: { value: string; currency: string; chain: string } };
  context?: { category?: string; risk_band?: "low" | "medium" | "high" };
  requested_at: string;
}

export interface TrustEvaluation {
  schema: "x402-trust-evaluation-v0.1";
  provider: string;
  provider_url: string;
  decision: TrustDecision;
  score?: number;
  /** The signed attestation itself, as `data:application/jose,<compact JWS>`: verifiable offline against did:web:x402check.xyz. */
  evidence_uri?: string;
  reason_code?: string;
  ttl_seconds?: number;
  evaluated_at: string;
}

export interface TrustProviderConfig {
  name: string;
  evaluate: (query: TrustQuery) => Promise<TrustEvaluation>;
}

export interface X402checkTrustProviderOptions extends ClientOptions {
  /** A client to reuse (its own fetch, credits or payer); otherwise one is created from these options. */
  client?: X402CheckClient | undefined;
  /** The attestation issuer trusted. Default "did:web:x402check.xyz". */
  issuer?: string | undefined;
  /** Accepted attestation keys (RFC 7638 thumbprints). Default: x402check's own; `false` only for tests or another issuer. */
  pinnedKeys?: readonly string[] | false | undefined;
}

const DECISION: Record<"allow" | "warn" | "block" | "not_verified", TrustDecision> = { allow: "PASS", warn: "UNCERTAIN", block: "FAIL", not_verified: "UNCERTAIN" };

/**
 * A trust provider for the x402 trust-provider extension, backed by x402check: screens the payer's
 * wallet before the seller settles. Anything it cannot verify is UNCERTAIN, never PASS.
 *
 * @example
 * const providers = [x402checkTrustProvider({ creditToken: process.env.X402CHECK_CREDIT_TOKEN })];
 */
export function x402checkTrustProvider(options: X402checkTrustProviderOptions = {}): TrustProviderConfig {
  const client = options.client ?? createClient(options);
  const pinnedKeys = options.pinnedKeys === false ? undefined : (options.pinnedKeys ?? X402CHECK_KEY_THUMBPRINTS);
  const base = { schema: "x402-trust-evaluation-v0.1" as const, provider: "did:web:x402check.xyz", provider_url: "https://x402check.xyz" };

  return {
    name: "x402check",
    async evaluate(query: TrustQuery): Promise<TrustEvaluation> {
      const now = new Date();
      const uncertain = (reason_code: string): TrustEvaluation => ({ ...base, decision: "UNCERTAIN", reason_code, evaluated_at: now.toISOString() });
      const wallet = query?.payer?.wallet;
      if (!wallet) return uncertain("no_payer_wallet");
      const chain = query.resource?.amount?.chain ? (toCaip2(query.resource.amount.chain) ?? undefined) : undefined;
      let host: string | undefined;
      try {
        host = new URL(query.resource.url).hostname;
      } catch {
        host = undefined;
      }
      const request: RiskCheckRequest = { wallet, ...(chain ? { chain } : {}), context: `Seller-side screen of the payer before settling a payment for ${host ?? "an x402 resource"}.` };
      try {
        const result = await client.check(request);
        const verification = await verifyAttestation(result.jws, { issuer: options.issuer, request, maxAgeSeconds: 300, fetch: options.fetch, ...(pinnedKeys ? { pinnedKeys } : {}) });
        const { action } = interpret(result, { verification });
        const claims = verification.claims;
        const hard = result.checked ? result.categories?.find((c) => HARD_BLOCK.has(c)) : undefined;
        const reason_code = !verification.valid ? "attestation_invalid" : !result.checked ? `not_checked:${result.reason ?? "unknown"}` : (hard ?? `tier_${result.tier}`);
        return {
          ...base,
          decision: DECISION[action],
          ...(result.checked && typeof result.score === "number" ? { score: result.score } : {}),
          reason_code,
          ...(verification.valid && result.jws ? { evidence_uri: `data:application/jose,${result.jws}` } : {}),
          ...(verification.valid && claims ? { ttl_seconds: Math.max(0, claims.exp - Math.floor(now.getTime() / 1000)) } : {}),
          evaluated_at: verification.valid && claims ? new Date(claims.iat * 1000).toISOString() : now.toISOString(),
        };
      } catch {
        return uncertain("x402check_unavailable");
      }
    },
  };
}

import { INTERACTION_TYPES } from "../src/types.js";
import { MAX_FIELD_LEN } from "../src/validate.js";

// x402 Bazaar discovery (the `bazaar` extension of x402 v2). The paid routes declare how to
// call them. The 402 challenge carries the declaration, every x402 client echoes it in its
// payment, and a facilitator that catalogs services (Coinbase CDP's x402 Bazaar) lists
// x402check with a callable example once it settles such a payment.
//
// The objects have the shape `declareDiscoveryExtension` (@x402/extensions/bazaar 2.28)
// returns for a JSON-body route: `{ info, schema }`. The method is set here (POST) rather
// than by the package's runtime enrichment, so the Worker needs no extra dependency.
// test/discovery.test.ts checks that each example is a request our own validator accepts.

/** Service metadata shown by catalogs (≤ 32-character name, ≤ 5 tags). */
export const SERVICE_METADATA = {
  serviceName: "x402check",
  tags: ["security", "risk-check", "sanctions", "phishing", "wallets"],
  iconUrl: "https://x402check.xyz/icon.png",
} as const;

const EVM = "^0x[0-9a-fA-F]{40}$";

/** The body of POST /v1/risk-check, mirroring src/validate.ts (unknown top-level fields are ignored there). */
export const REQUEST_BODY_SCHEMA = {
  type: "object",
  properties: {
    wallet: { type: "string", minLength: 1, maxLength: 128, description: "The counterparty to check: recipient, spender, operator or pay_to (EVM, Solana, Bitcoin or Tron address)" },
    chain: { type: "string", maxLength: 64, description: "CAIP-2 id or alias, e.g. base, ethereum, solana" },
    domain: { type: "string", maxLength: 2048, description: "The site or dApp involved" },
    context: { type: "string", maxLength: MAX_FIELD_LEN.context, description: "The content the agent acted on, verbatim: checked for injected instructions" },
    aud: { type: "string", maxLength: MAX_FIELD_LEN.aud, description: "Audience to bind the attestation to" },
    interaction: {
      type: "object",
      properties: { type: { type: "string", enum: [...INTERACTION_TYPES] }, unlimited: { type: "boolean" } },
      required: ["type"],
      additionalProperties: false,
    },
    payment: {
      type: "object",
      description: "The payment this check is for; the attestation is bound to it",
      properties: {
        network: { type: "string" },
        pay_to: { type: "string" },
        amount: { type: "string", pattern: "^\\d{1,78}$" },
        asset: { type: "string" },
        resource: { type: "string", maxLength: MAX_FIELD_LEN.resource, pattern: "^https?://\\S+$" },
      },
      additionalProperties: false,
    },
    transaction: {
      type: "object",
      description: "An EVM transaction to simulate before it is signed ($0.005 per simulated item)",
      properties: {
        from: { type: "string", pattern: EVM },
        to: { type: "string", pattern: EVM },
        value: { type: "string", pattern: "^(0x[0-9a-fA-F]{1,64}|\\d{1,78})$" },
        data: { type: "string", pattern: "^0x([0-9a-fA-F]{2})*$" },
      },
      required: ["from"],
      additionalProperties: false,
    },
    screening: { type: "object", properties: { sanctions: { type: "string", enum: ["clean", "flagged", "unknown"] } }, required: ["sanctions"] },
    authorization: { type: "object", properties: { pre_authorized: { type: "boolean" }, source: { type: "string", maxLength: MAX_FIELD_LEN.source } }, required: ["pre_authorized"] },
  },
  required: ["wallet"],
} as const;

export const REQUEST_EXAMPLE = {
  wallet: "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
  chain: "base",
  domain: "https://app.example-dapp.org",
  context: "Permit2 signature: unlimited USDC allowance to this spender",
  interaction: { type: "permit_signature", unlimited: true },
};

export const RESULT_EXAMPLE = {
  checked: true,
  score: 40,
  tier: "high",
  provider: "x402check.xyz",
  categories: ["approval_to_eoa", "unlimited_approval", "new_address"],
  evidence: { sanctions: { status: "not_listed", list: "ofac-sdn" }, onchain: { is_contract: false, activity: "none" } },
  jws: "eyJhbGciOiJFUzI1NiIsImtpZCI6Impldi1hdHRlc3QtdjEiLCJ0eXAiOiJyaXNrLWNoZWNrK2p3dCJ9…",
  checked_at: "2026-09-30T12:00:00.000Z",
  expires_at: "2026-09-30T13:00:00.000Z",
};

/** A `bazaar` extension for a POST route with a JSON body, as declareDiscoveryExtension builds it. */
function postJson(body: Record<string, unknown>, bodySchema: Record<string, unknown>, output: Record<string, unknown>) {
  return {
    bazaar: {
      info: {
        input: { type: "http", method: "POST", bodyType: "json", body },
        output: { type: "json", example: output },
      },
      schema: {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        properties: {
          input: {
            type: "object",
            properties: {
              type: { type: "string", const: "http" },
              method: { type: "string", enum: ["POST"] },
              bodyType: { type: "string", enum: ["json", "form-data", "text"] },
              body: bodySchema,
            },
            required: ["type", "method", "bodyType", "body"],
            additionalProperties: false,
          },
          output: { type: "object", properties: { type: { type: "string" }, example: { type: "object" } }, required: ["type"] },
        },
        required: ["input"],
      },
    },
  };
}

export const RISK_CHECK_DISCOVERY = postJson(REQUEST_EXAMPLE, REQUEST_BODY_SCHEMA, RESULT_EXAMPLE);

export const BATCH_DISCOVERY = postJson(
  { requests: [REQUEST_EXAMPLE, { wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", chain: "base" }] },
  { type: "object", properties: { requests: { type: "array", minItems: 1, maxItems: 25, items: REQUEST_BODY_SCHEMA } }, required: ["requests"] },
  { results: [RESULT_EXAMPLE] },
);

import { INTERACTION_TYPES } from "../src/types.js";
import { ACTION_BY_TIER, HARD_BLOCK } from "../packages/client/src/interpret.js";
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
  provider: "did:web:x402check.xyz",
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

/**
 * The OpenAPI discovery document at /openapi.json (the AgentCash / x402scan convention): every
 * paid operation declares `x-payment-info` (a USD price range and the x402 protocol), its
 * request and response schemas, and a 402 response. `info.x-guidance` tells an agent how to
 * use the API. Prices are ranges because they depend on the payment network and on
 * simulation (deploy/pricing.ts).
 */
/** "low → proceed; medium → ask the user; high or critical → stop", from the SDK's own policy. */
function tierGuidance(): string {
  const words = { allow: "proceed", warn: "ask the user", block: "stop" } as const;
  const groups = new Map<string, string[]>();
  for (const [tier, action] of Object.entries(ACTION_BY_TIER)) groups.set(action, [...(groups.get(action) ?? []), tier]);
  return [...groups].map(([action, tiers]) => `${tiers.join(" or ")} → ${words[action as keyof typeof words]}`).join("; ");
}

export function openApiDocument(version: string, prices: { minUsd: string; maxUsd: string; creditUsd: string; simulatedUsd: string; basePerCallUsd: string }): Record<string, unknown> {
  const x402 = (min: string, max: string) => ({ price: { mode: "dynamic", currency: "USD", min, max }, protocols: [{ x402: {} }] });
  const result = { type: "object", properties: { checked: { type: "boolean" }, score: { type: "integer", minimum: 0, maximum: 100 }, tier: { type: "string", enum: ["low", "medium", "high", "critical"] }, categories: { type: "array", items: { type: "string" }, description: "Always starts with the evaluated families \"intent_risk\" and \"behavioral\" (present in every verdict, not findings), then the specific findings behind the verdict" }, evidence: { type: "object" }, jws: { type: "string", description: "ES256 attestation from did:web:x402check.xyz" }, checked_at: { type: "string" }, expires_at: { type: "string" } }, required: ["checked"] };
  const responses = (schema: Record<string, unknown>) => ({
    "200": { description: "The verdict, with its signed attestation", content: { "application/json": { schema } } },
    "402": { description: "Payment Required: pay with x402 (the challenge lists every network), or send Authorization: Bearer x402c_… to pay from prepaid credits. Unpaid, a body that would be refused still gets the challenge, with the reason in request_error; it is never charged" },
    "422": { description: "Invalid request (with a payment or a credit token): the offending field is named, including an unknown field; nothing is charged" },
  });
  const maxBatch = (Number(prices.maxUsd) * 25).toFixed(3);
  return {
    openapi: "3.1.0",
    info: {
      title: "x402check",
      version,
      description: "Pre-payment risk checks for x402 agents and wallets: OFAC SDN, phishing and drainer feeds, a live watch of drainer infrastructure, transaction simulation and injected-instruction analysis. Every verdict is an ES256 attestation that states which checks ran.",
      "x-guidance": `Call POST /v1/risk-check before an agent sends funds, signs an approval, permit or order, or pays an x402 invoice. Send the real counterparty as "wallet" (recipient, spender, operator or pay_to), the chain, the site ("domain"), and the content that led you to act ("context", as written, leaving out secrets and personal data). Add "transaction" (EVM from/to/value/data) to have it simulated. Then follow the tier: ${tierGuidance()}; checked: false, or an attestation that does not verify or does not bind to your request → stop. These categories stop at any tier: ${[...HARD_BLOCK].join(", ")}. Pay per call with x402 (from $${prices.minUsd}; $${prices.basePerCallUsd} on Base), or buy prepaid credits once (POST /v1/credits {"amount_usd": 1}) and send Authorization: Bearer <token>: $${prices.creditUsd} a check ($${prices.simulatedUsd} simulated). Verify the attestation against did:web:x402check.xyz, bound to your request (@x402check/client verifyAttestation with request), before relying on it.`,
      contact: { name: "x402check", url: "https://github.com/caiovicentino/jev-risk-check-provider/issues" },
      license: { name: "MIT", url: "https://github.com/caiovicentino/jev-risk-check-provider/blob/main/LICENSE" },
    },
    servers: [{ url: "https://x402check.xyz" }],
    externalDocs: { url: "https://x402check.xyz/#integrate" },
    paths: {
      "/v1/risk-check": {
        post: {
          operationId: "riskCheck",
          summary: "Risk-check a counterparty before paying, with a signed attestation",
          tags: ["Risk"],
          "x-payment-info": x402(prices.minUsd, prices.maxUsd),
          requestBody: { required: true, content: { "application/json": { schema: REQUEST_BODY_SCHEMA, example: REQUEST_EXAMPLE } } },
          responses: responses(result),
        },
      },
      "/v1/risk-check/batch": {
        post: {
          operationId: "riskCheckBatch",
          summary: "Up to 25 risk checks in one call, billed per item",
          tags: ["Risk"],
          "x-payment-info": x402(prices.minUsd, maxBatch),
          requestBody: { required: true, content: { "application/json": { schema: BATCH_DISCOVERY.bazaar.schema.properties.input.properties.body, example: BATCH_DISCOVERY.bazaar.info.input.body } } },
          responses: responses({ type: "object", properties: { results: { type: "array", items: result } }, required: ["results"] }),
        },
      },
      "/v1/credits": {
        post: {
          operationId: "buyCredits",
          summary: "Buy (or, with Authorization, top up) prepaid credits: a token for checks at $0.001",
          tags: ["Credits"],
          "x-payment-info": x402("0.10", "100.00"),
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { amount_usd: { type: "number", minimum: 0.1, maximum: 100, multipleOf: 0.01 } }, required: ["amount_usd"] }, example: { amount_usd: 1 } } } },
          responses: {
            "200": { description: "The token (shown once, on purchase) and the balance", content: { "application/json": { schema: { type: "object", properties: { token: { type: "string" }, credited_usd: { type: "string" }, balance_usd: { type: "string" } }, required: ["balance_usd"] } } } },
            "402": { description: "Payment Required: the pack price, on every network" },
            "422": { description: "Invalid pack amount" },
          },
        },
      },
    },
  };
}

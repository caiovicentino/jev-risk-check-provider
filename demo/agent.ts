import { verifyJws } from "../src/jws.js";
import type { Jwk } from "../src/jws.js";

const RESOURCE = process.env.RESOURCE_URL ?? "http://localhost:8802/data";
const FACILITATOR = process.env.FACILITATOR_URL ?? "http://localhost:8801/verify";
const PROVIDER_CHECK = process.env.PROVIDER_CHECK_URL ?? "http://localhost:8800/v1/risk-check";
// Trust anchor pinned to the provider the agent chose — never the jwks_url a facilitator
// (or any other intermediary) hands back alongside the attestation.
const PINNED_JWKS = process.env.PROVIDER_JWKS_URL ?? new URL("/.well-known/jwks.json", PROVIDER_CHECK).toString();

export type AgentKey = { privatePem: string; publicPem: string; payerId: string };

export type AgentScenario = {
  name: string;
  operation_context: string;
  payer_domain?: string;
  payTo: string;
  prePaymentGate?: { recipientWallet: string; recipientDomain: string };
};

export async function runAgent(key: AgentKey, scenario: AgentScenario): Promise<void> {
  console.log(`\n=== scenario: ${scenario.name} ===`);

  if (scenario.prePaymentGate) {
    console.log(`[agent] pre-payment gate: scoring counterparty ${scenario.prePaymentGate.recipientDomain}`);
    const gateRes = await fetch(PROVIDER_CHECK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet: scenario.prePaymentGate.recipientWallet,
        chain: "solana",
        domain: scenario.prePaymentGate.recipientDomain,
        context: `agent intends to pay ${scenario.payTo} for ${RESOURCE}`,
      }),
    });
    const gate = (await gateRes.json()) as { checked: boolean; score?: number; tier?: string };
    console.log(`[agent] counterparty score=${gate.score ?? "-"} tier=${gate.tier ?? "-"}`);
    if (!gate.checked || (gate.score ?? 0) < 65) {
      console.log("[agent] REFUSED to pay: counterparty failed the pre-payment gate (JEV verdict)");
      return;
    }
    console.log("[agent] counterparty passed, proceeding to payment");
  }

  console.log("[agent] GET /data");
  const res402 = await fetch(RESOURCE);
  const paymentRequired = (await res402.json()) as {
    accepts: Array<{ amount: string; payTo: string }>;
    extensions: { "risk-check": { info: { min_score: number; risk_check_url: string } } };
  };
  console.log(`[agent] 402 received, min_score=${paymentRequired.extensions["risk-check"].info.min_score}`);

  const voucher = {
    resource: RESOURCE,
    payTo: scenario.payTo,
    amount: paymentRequired.accepts[0]?.amount ?? "50000",
    nonce: crypto.randomUUID(),
    ts: Date.now(),
    payer: key.payerId,
  };
  const { signVoucher } = await import("./voucher.js");
  const signature = signVoucher(voucher, key.privatePem);
  console.log(`[agent] signed voucher (ed25519) → facilitator`);

  const verifyRes = await fetch(FACILITATOR, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      voucher,
      signature,
      payer_public_pem: key.publicPem,
      operation_context: scenario.operation_context,
      payer_domain: scenario.payer_domain,
    }),
  });
  const verification = (await verifyRes.json()) as {
    isValid: boolean;
    invalidReason?: string;
    extensions?: { "risk-check": { score?: number; tier?: string; jws?: string; jwks_url?: string } };
  };
  console.log(`[facilitator] isValid=${verification.isValid}${verification.invalidReason ? ` reason=${verification.invalidReason}` : ""}`);
  const rc = verification.extensions?.["risk-check"];
  if (rc) console.log(`[facilitator] risk-check: score=${rc.score} tier=${rc.tier}`);

  if (verification.isValid && rc?.jws) {
    const jwksRes = await fetch(PINNED_JWKS);
    const jwks = (await jwksRes.json()) as { keys: Jwk[] };
    const kid = JSON.parse(Buffer.from(rc.jws.split(".")[0] ?? "", "base64url").toString("utf8")).kid as string | undefined;
    const key = jwks.keys.find((k) => k.kid === kid);
    const claims = key ? verifyJws(rc.jws, key) : null;
    if (!claims || claims.exp <= Math.floor(Date.now() / 1000)) {
      console.log("[agent] attestation failed verification against the pinned provider key — refusing to proceed");
      return;
    }
    console.log(`[agent] attestation verified against the pinned provider JWKS (${PINNED_JWKS}): score=${claims.score} tier=${claims.tier} iss=${claims.iss}`);
    const dataRes = await fetch(RESOURCE, { headers: { "X-Payment-Verified": "1" } });
    console.log(`[agent] resource response: ${dataRes.status} — ${await dataRes.text()}`);
  } else {
    console.log("[agent] payment rejected — resource not served");
  }
}

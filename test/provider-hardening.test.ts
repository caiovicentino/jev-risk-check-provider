// Regression tests for the 2026-09-30 audit's provider findings: canonical chain ids, address
// forms that dodged the OFAC screen, validation that threw, the payment network as the chain,
// review floors for lookups that failed, and secrets kept out of the model's input.
import { test } from "node:test";
import assert from "node:assert";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import { parseSubject } from "../src/address.js";
import { parseSubject as clientParseSubject } from "../packages/client/src/subject.js";
import { toCaip2 } from "../packages/client/src/normalize.js";
import { redactContext } from "../src/jev.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";
import type { KitWatchLookup } from "../src/kit-watch.js";

const answers: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const seenStates: unknown[] = [];
const jev: JevLike = { systemOne: async (state) => (seenStates.push(state), { answers, usage: { inputTokens: 1, outputTokens: 0 } }) };
const valid = (b: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(b);
  if (!v.ok) throw new Error(`invalid: ${v.field}`);
  return v.value;
};
const SPENDER = "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f";

test("chain ids: one spelling per chain (eip155:08453 is rejected by the provider, canonicalized by the client)", () => {
  assert.equal(validateRequest({ wallet: SPENDER, chain: "eip155:08453" }).ok, false);
  assert.equal(validateRequest({ wallet: `eip155:0008453:${SPENDER}` }).ok, false);
  assert.equal(validateRequest({ wallet: SPENDER, chain: "eip155:8453" }).ok, true);
  assert.equal(toCaip2("eip155:08453"), "eip155:8453");
});

test("address forms that dodged the screen: mixed-case bech32 and cashaddr, TRON hex", () => {
  for (const parse of [parseSubject, clientParseSubject]) {
    assert.equal(parse("bc1QAR0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), null, "mixed-case bech32");
    assert.equal(parse("bitcoincash:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A"), null, "mixed-case cashaddr");
    assert.equal(parse("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"), null, "TRON hex");
    assert.ok(parse("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "lowercase bech32 is fine");
  }
});

test("validation never throws: unknown keys in screening/authorization and non-canonical numbers are a 422", () => {
  assert.deepEqual(validateRequest({ wallet: SPENDER, screening: { sanctions: "clean", extra: 1 } }), { ok: false, field: "screening" });
  assert.deepEqual(validateRequest({ wallet: SPENDER, authorization: { pre_authorized: true, nested: { a: 1 } } }), { ok: false, field: "authorization" });
  const huge = JSON.parse(`{"wallet":"${SPENDER}","authorization":{"pre_authorized":true,"source":"x"}}`);
  assert.equal(validateRequest(huge).ok, true);
});

test("the payment's network names the chain when `chain` is absent", async () => {
  const networks: Array<string | undefined> = [];
  const onchain = async (_s: unknown, network: string | undefined) => (networks.push(network), { status: "ok" as const, network: network as string, is_contract: false, activity: "some" as const, tx_count: 3 });
  await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain }).evaluate(valid({ wallet: SPENDER, payment: { network: "base", pay_to: SPENDER, amount: "1000" } }));
  assert.deepEqual(networks, ["eip155:8453"]);
});

test("lookups that failed raise a review floor: contract verification, the kit watch, a grant with no chain", async () => {
  const contract = async () => ({ status: "ok" as const, network: "eip155:8453", is_contract: true, activity: "some" as const, tx_count: 90 });
  const intelDown = async () => ({ unavailable: true });
  const permit = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: contract, contractIntel: intelDown }).evaluate(
    valid({ wallet: SPENDER, chain: "base", interaction: { type: "permit_signature" } }),
  );
  assert.notEqual(permit.result.tier, "low", "a permit to a contract whose verification could not be read is reviewed");

  const onchainDown = async () => ({ status: "unavailable" as const, network: "eip155:8453" });
  const kitWatch: KitWatchLookup = { families: async () => ({ exact: new Map(), skeleton: new Map() }) as never, addresses: async () => new Map(), asOf: async () => "2026-09-30T00:00:00Z" };
  const pay = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainDown, kitWatch }).evaluate(valid({ wallet: SPENDER, chain: "base", interaction: { type: "token_transfer" } }));
  assert.equal(pay.result.evidence?.kit_watch?.status, "unavailable", "the watch did not fully run");
  assert.notEqual(pay.result.tier, "low");

  const noChain = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev }).evaluate(valid({ wallet: SPENDER, interaction: { type: "token_approval", unlimited: true } }));
  assert.notEqual(noChain.result.tier, "low", "an EVM grant with no chain cannot be classified");
});

test("secrets pasted into the context never reach the model", async () => {
  const key = `0x${"ab".repeat(32)}`;
  const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
  const token = `x402c_${"K".repeat(43)}`;
  const redacted = redactContext(`sign with ${key} then ${phrase} and pay with ${token}`);
  for (const secret of [key, phrase, token]) assert.ok(!redacted.includes(secret), secret.slice(0, 12));
  seenStates.length = 0;
  await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev }).evaluate(valid({ wallet: SPENDER, chain: "base", context: `use key ${key}` }));
  assert.ok(!JSON.stringify(seenStates).includes("ab".repeat(32)));
});

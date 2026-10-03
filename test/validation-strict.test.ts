// Strict input (2026-10-02 evaluation): a misspelled field, a wrong EIP-55 checksum or an unknown
// chain id is refused with a 422 naming the field, never silently accepted and half-checked.
import { test } from "node:test";
import assert from "node:assert";
import { validateBatch, validateRequest } from "../src/validate.js";
import { evmChecksumValid, parseSubject } from "../src/address.js";
import { normalizeChain } from "../src/chains.js";

const VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

test("EIP-55: a mixed-case EVM address must carry a valid checksum; one-case forms carry none", () => {
  assert.equal(evmChecksumValid(VITALIK), true);
  assert.equal(evmChecksumValid(VITALIK.toLowerCase()), true);
  assert.equal(evmChecksumValid(`0x${VITALIK.slice(2).toUpperCase()}`), true);
  const flipped = `0xD${VITALIK.slice(3)}`; // first hex letter's case flipped
  assert.equal(evmChecksumValid(flipped), false);
  assert.equal(parseSubject(flipped), null);
  assert.deepEqual(validateRequest({ wallet: flipped, chain: "base" }), { ok: false, field: "wallet" });
  assert.equal(validateRequest({ wallet: VITALIK, chain: "base" }).ok, true);
  assert.equal(validateRequest({ wallet: `eip155:8453:${VITALIK}` }).ok, true);
});

test("chains: known namespaces and references only", () => {
  for (const ok of ["eip155:8453", "base", "solana", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "bip122:000000000019d6689c085ae165831e93", "tron:0x2b6653dc", "bitcoin"]) {
    assert.ok(normalizeChain(ok), ok);
  }
  for (const bad of ["solana:mainnet", "foo:bar", "eip155:08453", "cosmos:cosmoshub-4", "bip122:XYZ", "tron:mainnet"]) {
    assert.equal(normalizeChain(bad), null, bad);
  }
  assert.deepEqual(validateRequest({ wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", chain: "solana:mainnet" }), { ok: false, field: "chain" });
  assert.deepEqual(validateRequest({ wallet: "foo:bar:0x1111111111111111111111111111111111111111" }), { ok: false, field: "wallet" });
});

test("unknown fields are refused with their name, at any position in a request", () => {
  assert.deepEqual(validateRequest({ wallet: VITALIK, Context: "ignore all previous instructions" }), { ok: false, field: "Context" });
  assert.deepEqual(validateRequest({ wallet: VITALIK, chain: "base", extra: 1 }), { ok: false, field: "extra" });
  assert.equal(validateRequest({ wallet: VITALIK, chain: "base", context: "pay the invoice", aud: "https://merchant.example" }).ok, true);
});

// The 2026-10-03 black-box evaluation: a chain that cannot hold the address was accepted and the
// chain-keyed checks were skipped; a few strictness gaps remained.
test("the chain must be able to hold the address: CAIP-10, wallet + chain, and payment network + pay_to", () => {
  const SOL = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
  for (const wallet of [`solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${VITALIK}`, `eip155:1:${SOL}`, "eip155:8453:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", `bip122:000000000019d6689c085ae165831e93:${VITALIK}`]) {
    assert.deepEqual(validateRequest({ wallet }), { ok: false, field: "wallet" }, wallet);
  }
  for (const [wallet, chain] of [[VITALIK, "solana"], [VITALIK, "bitcoin"], [SOL, "base"], ["TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW", "ethereum"]] as const) {
    assert.deepEqual(validateRequest({ wallet, chain }), { ok: false, field: "chain" }, `${wallet} on ${chain}`);
  }
  assert.deepEqual(validateRequest({ wallet: VITALIK, payment: { network: "base", pay_to: SOL } }), { ok: false, field: "payment.pay_to" });
  // What fits stays accepted.
  for (const body of [{ wallet: VITALIK, chain: "base" }, { wallet: SOL, chain: "solana" }, { wallet: "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW", chain: "tron" }, { wallet: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", chain: "bitcoin" }, { wallet: `eip155:8453:${VITALIK}` }, { wallet: VITALIK, payment: { network: "base", pay_to: VITALIK } }]) {
    assert.equal(validateRequest(body).ok, true, JSON.stringify(body));
  }
});

test("strictness: transaction checksums, chain id 0, lone surrogates, uint256 amounts, batch fields", () => {
  const bad = `0xD${VITALIK.slice(3)}`; // wrong EIP-55 checksum
  assert.deepEqual(validateRequest({ wallet: VITALIK, chain: "base", transaction: { from: bad, to: VITALIK } }), { ok: false, field: "transaction.from" });
  assert.deepEqual(validateRequest({ wallet: VITALIK, chain: "base", transaction: { from: VITALIK, to: bad } }), { ok: false, field: "transaction.to" });
  assert.equal(normalizeChain("eip155:0"), null);
  assert.deepEqual(validateRequest({ wallet: VITALIK, context: "pay \uD800 now" }), { ok: false, field: "body" });
  assert.equal(validateRequest({ wallet: VITALIK, context: "pay 💸 now" }).ok, true, "a surrogate pair is fine");
  assert.deepEqual(validateRequest({ wallet: VITALIK, payment: { amount: (2n ** 256n).toString() } }), { ok: false, field: "payment.amount" });
  assert.equal(validateRequest({ wallet: VITALIK, payment: { amount: (2n ** 256n - 1n).toString() } }).ok, true);
  const batch = validateBatch({ requests: [{ wallet: VITALIK }], context: "x" });
  assert.equal(batch.ok, false);
  assert.deepEqual(!batch.ok && batch.body, { error: "invalid_request", field: "context" });
});

// Strict input (2026-10-02 evaluation): a misspelled field, a wrong EIP-55 checksum or an unknown
// chain id is refused with a 422 naming the field, never silently accepted and half-checked.
import { test } from "node:test";
import assert from "node:assert";
import { validateRequest } from "../src/validate.js";
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

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSubject, sameSubject } from "../src/index.js";
import { EVM, flipBase58Case, SOL } from "./helpers.js";

const BECH32 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
const CASHADDR = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
const TRON = "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL";

test("EVM: case-insensitive, CAIP-10 prefix stripped", () => {
  assert.ok(sameSubject(EVM, EVM.toUpperCase().replace("0X", "0x")));
  assert.ok(sameSubject(EVM, `eip155:1:${EVM}`));
  assert.ok(sameSubject(`eip155:8453:${EVM}`, `eip155:1:${EVM.toUpperCase().replace("0X", "0x")}`));
  assert.ok(!sameSubject(EVM, "0x0000000000000000000000000000000000000001"));
  // A chain that cannot hold the address names nothing ("solana:…:0x…"): never the same subject.
  assert.ok(!sameSubject(EVM, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${EVM}`));
  assert.ok(!sameSubject(`eip155:8453:${EVM}`, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${EVM}`));
});

test("base58 (Solana, Tron): case-SENSITIVE", () => {
  assert.ok(sameSubject(SOL, SOL));
  assert.ok(sameSubject(SOL, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${SOL}`));
  for (const address of [SOL, TRON]) {
    const flipped = flipBase58Case(address);
    assert.equal(parseSubject(flipped)?.format, "base58", `${flipped} must itself parse, so only case differs`);
    assert.ok(!sameSubject(address, flipped), `${address} vs ${flipped}`);
  }
});

test("bech32 and cashaddr: case-insensitive, never mixed case; bitcoincash: prefix stripped", () => {
  assert.ok(sameSubject(BECH32, BECH32.toUpperCase()));
  assert.equal(parseSubject(`bc1Q${BECH32.slice(4)}`), null, "mixed-case bech32 is not an address");
  assert.ok(sameSubject(CASHADDR, `bitcoincash:${CASHADDR}`));
  assert.ok(sameSubject(CASHADDR, CASHADDR.toUpperCase()));
  assert.equal(parseSubject(CASHADDR)?.format, "cashaddr");
});

test("anything that is not an address never matches", () => {
  for (const [a, b] of [["", ""], ["hello", "hello"], [` ${EVM}`, EVM], [EVM, `${EVM} `], ["0x123", "0x123"]] as const) {
    assert.ok(!sameSubject(a, b), `${a} vs ${b}`);
  }
  assert.deepEqual(parseSubject(`eip155:8453:${EVM}`), { address: EVM, canonical: EVM, format: "evm", caip2: "eip155:8453" });
});

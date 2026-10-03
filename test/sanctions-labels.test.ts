// OFAC's "Digital Currency Address - <TICKER>" label is not a chain discriminator (raised on
// x402-foundation/x402#2300, 2026-10-03): the SDN list carries a TRON-format address labelled XBT
// and Bitcoin/Omni-format addresses labelled USDT. The screen keys on the address format, never
// on the label, so a mislabelled entry is still found, and every listed address the API accepts
// as a subject screens as listed.
import { test } from "node:test";
import assert from "node:assert";
import { OFAC_SDN_ADDRESSES } from "../src/data/ofac-sdn.js";
import { parseSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";

const TRON = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
const BITCOIN = /^(bc1[02-9ac-hj-np-z]{8,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/;

test("mislabelled OFAC entries (XBT label on a TRON address, USDT on Bitcoin) screen as listed", (t) => {
  const mislabelled = OFAC_SDN_ADDRESSES.filter(([a, ticker]) => (ticker === "XBT" && TRON.test(a)) || (ticker === "USDT" && BITCOIN.test(a)));
  if (!mislabelled.length) return t.skip("this snapshot carries no mislabelled entry");
  for (const [address, ticker] of mislabelled) {
    const subject = parseSubject(address);
    assert.ok(subject, address);
    assert.equal(screenSubject(subject).status, "listed", `${ticker}-labelled ${address}`);
  }
});

test("every listed address the API accepts as a subject screens as listed, whatever its label", () => {
  let screened = 0;
  for (const [address, ticker] of OFAC_SDN_ADDRESSES) {
    const subject = parseSubject(address);
    if (!subject) continue;
    screened++;
    assert.equal(screenSubject(subject).status, "listed", `${ticker} ${address}`);
  }
  // Only formats the API does not take as subjects (a Monero address) are left out.
  assert.ok(screened >= OFAC_SDN_ADDRESSES.length - 5, `${screened} of ${OFAC_SDN_ADDRESSES.length}`);
});

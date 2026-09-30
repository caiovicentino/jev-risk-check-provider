// Production probe for single-use payments (v0.6.0). One check is paid per call; the moment the
// paid request goes out, two exact copies of it (same PAYMENT-SIGNATURE) go out too, so all three
// verify before anything settles. Exactly one may be evaluated and settled; the other two must
// get 409 payment_already_used. A copy sent after settlement must be refused as well (the
// facilitator then sees the authorization as used: 402, or the claim store: 409).
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/replay.ts
//
// Cost: one check on the payment network ($0.0035 on Base), paid by the probe payer to
// x402check's own pay_to. The copies are refused before any evaluation.
import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt } from "./paid-fetch.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const BODY = JSON.stringify({ wallet: "0x1111111111111111111111111111111111111111", chain: "base" });

type Outcome = { who: string; status: number; error: string | null; settled: boolean; transaction?: string | undefined };

async function outcome(who: string, res: Response): Promise<Outcome> {
  const receipt = settlementReceipt(res.headers);
  const error = res.status === 200 ? null : (((await res.clone().json().catch(() => ({}))) as { error?: string }).error ?? null);
  return { who, status: res.status, error, settled: receipt?.success === true, ...(receipt?.transaction ? { transaction: receipt.transaction } : {}) };
}

async function main(): Promise<void> {
  let signature: string | null = null;
  const copies: Array<Promise<Outcome>> = [];
  const send = (header: string) => fetch(`${BASE}/v1/risk-check`, { method: "POST", headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": header }, body: BODY });
  // The paid retry carries the PAYMENT-SIGNATURE: two copies leave at the same moment.
  const observing = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const sent = input instanceof Request ? input.headers : new Headers(init?.headers);
    const header = sent.get("payment-signature");
    if (header && !signature) {
      signature = header;
      for (const who of ["copy 1", "copy 2"]) copies.push(send(header).then((r) => outcome(who, r)));
    }
    return fetch(input, init);
  }) as typeof fetch;
  const pay = await buildPayFetch(observing);
  const original = await outcome("original", await pay(`${BASE}/v1/risk-check`, { method: "POST", headers: { "content-type": "application/json" }, body: BODY }));
  if (!signature) throw new Error("no payment was made: nothing to replay");
  const concurrent = [original, ...(await Promise.all(copies))];
  for (const o of concurrent) console.log(`${o.who}: HTTP ${o.status} ${o.error ?? ""}${o.settled ? ` settled ${o.transaction}` : ""}`);
  const later = await outcome("after settlement", await send(signature));
  console.log(`${later.who}: HTTP ${later.status} ${later.error ?? ""}`);

  const winners = concurrent.filter((o) => o.status === 200 && o.settled);
  const losers = concurrent.filter((o) => o !== winners[0]);
  const pass =
    winners.length === 1 &&
    losers.every((o) => o.status === 409 && o.error === "payment_already_used" && !o.settled) &&
    (later.status === 402 || later.status === 409) &&
    !later.settled;
  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    // The payment itself is not published: only a hash of the signature header.
    payment_signature_sha256: createHash("sha256").update(signature).digest("hex").slice(0, 16),
    concurrent,
    after_settlement: later,
    pass,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/replay-report.json`, JSON.stringify(report, null, 2));
  console.log(pass ? "PASS  one evaluation and one settlement for three copies; the late copy was refused" : "FAIL  see the outcomes above");
  if (!pass) process.exit(1);
}

main().catch((err) => {
  console.error(String(err));
  process.exit(1);
});

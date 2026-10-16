// Production probe for a client that disconnects before settlement (v0.6.15). The paid request
// leaves with its payment and is abandoned `--abandon-ms` later (default 1500: past the payment's
// verification, while the check is evaluated). The Worker must then settle nothing (it answers 499
// to nobody) and release the payment's claim, so the same signed payment, sent again a little
// later, is evaluated and settled once.
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/disconnect.ts [--abandon-ms 1500]
//   npx tsx eval/disconnect.ts --credits [--abandon-ms 600]
//
// With --credits the check is paid from the probe credits (the token in ~/.config/paysol, never
// printed, sent to production only): since 0.6.17 a check abandoned before it starts is refunded,
// and one abandoned during its evaluation is charged once (its verdict was produced). It costs at
// most $0.001, never more.
//
// Cost: one check on the payment network ($0.0035 on Base), paid by the probe payer to
// x402check's own pay_to. If the abandoned request had been settled, the resend is refused
// (409 or 402) and the probe fails: the cost is the same either way.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { numberFlag } from "./flags.js";
import { buildPayFetch, settlementReceipt } from "./paid-fetch.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const BODY = JSON.stringify({ wallet: "0x1111111111111111111111111111111111111111", chain: "base" });
const ABANDON_AFTER_MS = numberFlag("abandon-ms", 1500);
const RESEND_AFTER_MS = 15_000;

/** The credits variant: one check abandoned mid-evaluation, then the balance compared. */
async function credits(deployed: { version?: string; commit?: string }): Promise<void> {
  // The token is a bearer secret with a balance: it goes to production only, never to another X402CHECK_BASE.
  if (new URL(BASE).origin !== "https://x402check.xyz") throw new Error("--credits sends the probe credits' token: run it against https://x402check.xyz only");
  const token = readFileSync(`${homedir()}/.config/paysol/x402check-credit-token`, "utf8").trim();
  const balance = async () => ((await (await fetch(`${BASE}/v1/credits`, { headers: { Authorization: `Bearer ${token}` }, redirect: "manual" })).json()) as { balance_usd?: string }).balance_usd ?? null;
  const before = await balance();
  if (!before || Number(before.replace("$", "")) < 0.001) throw new Error(`the probe credits cannot pay for a check (balance ${before ?? "unknown"})`);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ABANDON_AFTER_MS);
  const started = Date.now();
  const abandoned = await fetch(`${BASE}/v1/risk-check`, { method: "POST", headers: { "content-type": "application/json", Authorization: `Bearer ${token}` }, body: BODY, signal: controller.signal, redirect: "manual" }).then(
    (res) => ({ status: res.status, charged: res.headers.get("x-credits-charged") }),
    (err: unknown) => ({ status: 0, charged: null, error: String(err instanceof Error ? err.name : err) }),
  );
  console.log(`abandoned after ${Date.now() - started} ms: ${abandoned.status === 0 ? "no answer (aborted)" : `HTTP ${abandoned.status}`}`);
  await new Promise((r) => setTimeout(r, RESEND_AFTER_MS));
  const after = await balance();
  console.log(`balance ${before} before, ${after} after`);
  // Since 0.6.17 a check abandoned before it starts is refunded, and one abandoned during its evaluation is
  // charged once (the verdict was produced): never more than the one check, never a free one in a loop.
  const usd = (v: string | null) => (v ? Number(v.replace("$", "")) : Number.NaN);
  const charged = Math.round((usd(before) - usd(after)) * 1e6) / 1e6;
  const pass = abandoned.status === 0 && (charged === 0 || charged === 0.001);
  const report = { timestamp: new Date().toISOString(), base: BASE, version: deployed.version ?? null, commit: deployed.commit ?? null, mode: "credits", abandon_after_ms: ABANDON_AFTER_MS, abandoned, balance_before: before, balance_after: after, charged_usd: charged, pass };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/disconnect-credits-v${deployed.version ?? "unknown"}-${ABANDON_AFTER_MS}ms-report.json`, JSON.stringify(report, null, 2));
  console.log(pass ? `PASS  the abandoned check cost $${charged} (0 when it had not started, one check when its verdict was produced)` : "FAIL  see the outcomes above");
  if (!pass) process.exit(1);
}

async function main(): Promise<void> {
  const deployed = (await (await fetch(`${BASE}/healthz`)).json()) as { version?: string; commit?: string };
  if (process.argv.includes("--credits")) return credits(deployed);
  let signature: string | null = null;
  // The paid retry carries the PAYMENT-SIGNATURE: that request is abandoned shortly after it leaves.
  const abandoning = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const header = (input instanceof Request ? input.headers : new Headers(init?.headers)).get("payment-signature");
    if (!header) return fetch(input, init);
    signature = header;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ABANDON_AFTER_MS);
    return fetch(input, { ...init, signal: controller.signal });
  }) as typeof fetch;
  const pay = await buildPayFetch(abandoning);
  const started = Date.now();
  const abandoned = await pay(`${BASE}/v1/risk-check`, { method: "POST", headers: { "content-type": "application/json" }, body: BODY }).then(
    (res) => ({ status: res.status, settled: settlementReceipt(res.headers)?.success === true }),
    (err: unknown) => ({ status: 0, settled: false, error: String(err instanceof Error ? err.name : err) }),
  );
  if (!signature) throw new Error("no payment was made: nothing to resend");
  console.log(`abandoned after ${Date.now() - started} ms: ${abandoned.status === 0 ? "no answer (aborted)" : `HTTP ${abandoned.status}`}`);

  await new Promise((r) => setTimeout(r, RESEND_AFTER_MS));
  const res = await fetch(`${BASE}/v1/risk-check`, { method: "POST", headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": signature }, body: BODY });
  const receipt = settlementReceipt(res.headers);
  const error = res.status === 200 ? null : (((await res.clone().json().catch(() => ({}))) as { error?: string }).error ?? null);
  const resent = { status: res.status, error, settled: receipt?.success === true, ...(receipt?.transaction ? { transaction: receipt.transaction } : {}) };
  console.log(`resent after ${RESEND_AFTER_MS / 1000} s: HTTP ${resent.status} ${error ?? ""}${resent.settled ? ` settled ${resent.transaction}` : ""}`);

  // The abandoned request got no settled answer, and the same payment then paid for exactly one check.
  const pass = abandoned.status === 0 && resent.status === 200 && resent.settled;
  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    version: deployed.version ?? null,
    commit: deployed.commit ?? null,
    // The payment itself is not published: only a hash of the signature header.
    payment_signature_sha256: createHash("sha256").update(signature).digest("hex").slice(0, 16),
    abandon_after_ms: ABANDON_AFTER_MS,
    resend_after_ms: RESEND_AFTER_MS,
    abandoned,
    resent,
    pass,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/disconnect-v${deployed.version ?? "unknown"}-${ABANDON_AFTER_MS}ms-report.json`, JSON.stringify(report, null, 2));
  console.log(pass ? "PASS  the abandoned request settled nothing; the same payment then paid for one check" : "FAIL  see the outcomes above");
  if (!pass) process.exit(1);
}

main().catch((err) => {
  console.error(String(err));
  process.exit(1);
});

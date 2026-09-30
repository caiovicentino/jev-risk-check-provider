// x402check_pay, the MCP server's guarded payment tool, against PRODUCTION: one real x402
// payment made through the tool, to x402check itself (our own pay_to: no third party is paid).
// It proves the real payment path end to end: the 402, the payer's gate, the EIP-3009
// signature, the paid retry, the facilitator's settlement on Base, and the receipt.
//
//   npx tsx eval/mcp-pay.ts
//
// Payer: the probe wallet (~/.config/paysol/payer-evm.key). Checks: the probe's prepaid credits
// (~/.config/paysol/x402check-credit-token). Neither is printed or written to the report.
// Cost: $0.0035 on Base, paid to x402check's pay_to. The payee is x402check's own address, so
// the guard allows it without a check (a trusted payee); eval/pay-guard.ts measures the check
// path on real merchants' payees.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { callTool, connect } from "../packages/mcp/test/helpers.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";

async function main(): Promise<void> {
  const payerKey = readFileSync(`${homedir()}/.config/paysol/payer-evm.key`, "utf8").trim();
  const creditToken = readFileSync(`${homedir()}/.config/paysol/x402check-credit-token`, "utf8").trim();
  const session = await connect({ baseUrl: BASE, payerKey, creditToken, maxPaymentUsd: 0.01, budgetUsd: 0.01, timeoutMs: 60_000 });
  const started = Date.now();
  try {
    const r = await callTool(session.client, "x402check_pay", {
      url: `${BASE}/v1/risk-check`,
      method: "POST",
      body: JSON.stringify({ wallet: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain: "base" }),
      context: "eval/mcp-pay: a paid risk check bought through x402check_pay",
    });
    const s = r.structuredContent as Record<string, unknown>;
    const response = s.response as { status?: number; body?: string } | undefined;
    let result: Record<string, unknown> | undefined;
    try {
      result = response?.body ? (JSON.parse(response.body) as Record<string, unknown>) : undefined;
    } catch {
      result = undefined;
    }
    const secrets = [payerKey.slice(2).toLowerCase(), creditToken.toLowerCase()];
    const leaked = secrets.some((x) => JSON.stringify(r).toLowerCase().includes(x));
    const report = {
      timestamp: new Date().toISOString(),
      base: BASE,
      duration_ms: Date.now() - started,
      outcome: s.outcome,
      payment_sent: s.payment_sent,
      action: s.action,
      reasons: s.reasons,
      payment: s.payment,
      response: { status: response?.status, result_checked: result?.checked, result_tier: result?.tier, result_has_jws: typeof result?.jws === "string" },
      secrets_in_output: leaked,
      text: r.text.split("\n").slice(0, 8),
    };
    mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
    writeFileSync(`${EVAL_EVIDENCE_DIR}/mcp-pay-report.json`, JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 1));
    if (leaked) throw new Error("a secret appeared in the tool output");
  } finally {
    await session.close();
  }
}

main().catch((err) => {
  console.error(String(err).slice(0, 300));
  process.exit(1);
});

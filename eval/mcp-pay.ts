// x402check_pay, the MCP server's guarded payment tool, against PRODUCTION: one real x402
// payment made through the tool, to x402check itself (our own pay_to: no third party is paid).
// It proves the real payment path end to end: the 402, the payer's gate, the EIP-3009
// signature, the paid retry, the facilitator's settlement on Base, and the receipt.
//
//   npm --prefix packages/mcp run build && npx tsx eval/mcp-pay.ts
//
// The server is the built binary (packages/mcp/dist/index.js), driven over stdio with plain
// JSON-RPC, exactly as an MCP client drives it. Payer: the probe wallet
// (~/.config/paysol/payer-evm.key). Checks: the probe's prepaid credits
// (~/.config/paysol/x402check-credit-token). Both reach the server as environment variables,
// as an MCP client passes them; neither is printed or written to the report.
// Cost: $0.0035 on Base, paid to x402check's pay_to. The payee is x402check's own address, so
// the guard allows it without a check (a trusted payee); eval/pay-guard.ts measures the check
// path on real merchants' payees.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { EVAL_EVIDENCE_DIR } from "./harness.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const BIN = fileURLToPath(new URL("../packages/mcp/dist/index.js", import.meta.url));

type RpcMessage = { id?: number; result?: Record<string, unknown>; error?: { message?: string } };

async function main(): Promise<void> {
  if (!existsSync(BIN)) throw new Error("build the MCP server first: npm --prefix packages/mcp run build");
  const payerKey = readFileSync(`${homedir()}/.config/paysol/payer-evm.key`, "utf8").trim();
  const creditToken = readFileSync(`${homedir()}/.config/paysol/x402check-credit-token`, "utf8").trim();
  const child = spawn(process.execPath, [BIN], {
    env: { ...process.env, X402CHECK_BASE_URL: BASE, X402CHECK_PAYER_KEY: payerKey, X402CHECK_CREDIT_TOKEN: creditToken, X402CHECK_MAX_PAYMENT_USD: "0.01", X402CHECK_BUDGET_USD: "0.01", X402CHECK_TIMEOUT_MS: "60000" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
  const pending = new Map<number, (m: RpcMessage) => void>();
  let buffer = "";
  child.stdout.on("data", (d: Buffer) => {
    buffer += d.toString();
    for (let nl = buffer.indexOf("\n"); nl >= 0; nl = buffer.indexOf("\n")) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      const message = JSON.parse(line) as RpcMessage;
      if (typeof message.id === "number") pending.get(message.id)?.(message);
    }
  });
  const send = (message: Record<string, unknown>) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
  const call = (id: number, method: string, params: Record<string, unknown>) =>
    new Promise<RpcMessage>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${method}: no answer within 120 s`)), 120_000);
      pending.set(id, (m) => (clearTimeout(timer), resolve(m)));
      send({ id, method, params });
    });

  const started = Date.now();
  try {
    const init = await call(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "eval-mcp-pay", version: "0" } });
    const server = (init.result?.serverInfo as { version?: string } | undefined)?.version;
    send({ method: "notifications/initialized" });
    const answer = await call(2, "tools/call", {
      name: "x402check_pay",
      arguments: {
        url: `${BASE}/v1/risk-check`,
        method: "POST",
        body: JSON.stringify({ wallet: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain: "base" }),
        context: "eval/mcp-pay: a paid risk check bought through x402check_pay",
      },
    });
    if (answer.error) throw new Error(`tools/call failed: ${answer.error.message ?? "unknown"}`);
    const s = (answer.result?.structuredContent ?? {}) as Record<string, unknown>;
    const text = ((answer.result?.content as Array<{ text?: string }> | undefined)?.[0]?.text ?? "").split("\n");
    const response = s.response as { status?: number; body?: string } | undefined;
    let result: Record<string, unknown> | undefined;
    try {
      result = response?.body ? (JSON.parse(response.body) as Record<string, unknown>) : undefined;
    } catch {
      result = undefined;
    }
    const secrets = [payerKey.slice(2).toLowerCase(), creditToken.toLowerCase()];
    const leaked = secrets.some((x) => `${JSON.stringify(answer)}${stderr}`.toLowerCase().includes(x));
    const report = {
      timestamp: new Date().toISOString(),
      base: BASE,
      server: `@x402check/mcp ${server ?? "?"} (packages/mcp/dist/index.js over stdio)`,
      duration_ms: Date.now() - started,
      outcome: s.outcome,
      payment_sent: s.payment_sent,
      action: s.action,
      reasons: s.reasons,
      payment: s.payment,
      response: { status: response?.status, result_checked: result?.checked, result_tier: result?.tier, result_has_jws: typeof result?.jws === "string" },
      secrets_in_output_or_stderr: leaked,
      text: text.slice(0, 8),
    };
    mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
    writeFileSync(`${EVAL_EVIDENCE_DIR}/mcp-pay-report.json`, JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 1));
    if (leaked) throw new Error("a secret appeared in the tool output or on stderr");
  } finally {
    child.kill();
  }
}

main().catch((err) => {
  console.error(String(err).slice(0, 300));
  process.exit(1);
});

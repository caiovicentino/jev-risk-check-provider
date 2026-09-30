#!/usr/bin/env node
// x402check MCP server over stdio. stdout carries MCP messages only: diagnostics go to stderr.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { configFromEnv, createPayer, createX402CheckServer, DEFAULT_BUDGET_USD, DEFAULT_MAX_PAYMENT_USD } from "./server.js";
import { VERSION } from "./version.js";

const HELP = `x402check-mcp ${VERSION}: MCP server (stdio) for x402check pre-payment risk checks,
and x402 payments made only after x402check clears the payee (x402check_pay).

Every check is paid: $0.001 from prepaid credits, or per call via x402 in USDC
($0.0035 on Base, gasless for the payer).

Environment:
  X402CHECK_CREDIT_TOKEN     prepaid credit token (x402c_…, from POST /v1/credits): checks are
                             debited from its balance, with no payment round trip. A secret.
  X402CHECK_PAYER_KEY        EVM private key (0x + 64 hex) of a DEDICATED, low-balance wallet
                             holding a little USDC on Base. It pays the x402 resources that
                             x402check_pay clears, and per check when there are no credits.
  X402CHECK_MAX_PAYMENT_USD  per-payment cap, a check or a resource (default 0.05)
  X402CHECK_BUDGET_USD       total payer spend for this server process (default 1.00)
  X402CHECK_BASE_URL         API origin (default https://x402check.xyz)
  X402CHECK_ISSUER           trusted attestation issuer (default did:web:x402check.xyz)
  X402CHECK_TIMEOUT_MS       per API call (default 30000)

Tools: x402check_check, x402check_pay, x402check_verify_attestation, x402check_methodology`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--version") || args.includes("-v")) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(`${HELP}\n`);
    return;
  }
  const config = configFromEnv(process.env);
  const server = createX402CheckServer(config);
  // stderr only (stdout carries MCP messages); the public address, never the key.
  const payer = config.payerKey ? createPayer({ privateKey: config.payerKey, maxPaymentUsd: config.maxPaymentUsd, budgetUsd: config.budgetUsd }).address : undefined;
  const limits = `max $${(config.maxPaymentUsd ?? DEFAULT_MAX_PAYMENT_USD).toFixed(3)} per payment, budget $${(config.budgetUsd ?? DEFAULT_BUDGET_USD).toFixed(2)}`;
  if (config.creditToken) {
    process.stderr.write(`x402check-mcp: checks paid from prepaid credits (X402CHECK_CREDIT_TOKEN)${payer ? `; x402check_pay pays from ${payer} (${limits})` : "; x402check_pay needs X402CHECK_PAYER_KEY"}\n`);
  } else if (payer) {
    process.stderr.write(`x402check-mcp: paying from ${payer}: checks, and the resources x402check_pay clears (${limits})\n`);
  } else {
    process.stderr.write("x402check-mcp: no X402CHECK_CREDIT_TOKEN or X402CHECK_PAYER_KEY: checks are paid and will return not_verified until one is configured\n");
  }
  await server.connect(new StdioServerTransport());
  const shutdown = (): void => {
    server.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  process.stderr.write(`x402check-mcp: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});

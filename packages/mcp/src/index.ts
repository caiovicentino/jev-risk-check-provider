#!/usr/bin/env node
// x402check MCP server over stdio. stdout carries MCP messages only: diagnostics go to stderr.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { configFromEnv, createPayer, createX402CheckServer, DEFAULT_BUDGET_USD, DEFAULT_MAX_PAYMENT_USD } from "./server.js";
import { VERSION } from "./version.js";

const HELP = `x402check-mcp ${VERSION}: MCP server (stdio) for x402check pre-payment risk checks.

Every check is paid via x402: $0.001 in USDC per evaluation, gasless for the payer.

Environment:
  X402CHECK_PAYER_KEY        EVM private key (0x + 64 hex) of a DEDICATED, low-balance wallet
                             holding a little USDC on Base. It pays for checks (Base first).
  X402CHECK_MAX_PAYMENT_USD  per-payment cap (default 0.05)
  X402CHECK_BUDGET_USD       total spend for this server process (default 1.00)
  X402CHECK_BASE_URL         API origin (default https://x402check.xyz)
  X402CHECK_ISSUER           trusted attestation issuer (default did:web:x402check.xyz)
  X402CHECK_TIMEOUT_MS       per API call (default 30000)

Tools: x402check_check, x402check_verify_attestation, x402check_methodology`;

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
  if (config.payerKey) {
    const address = createPayer({ privateKey: config.payerKey, maxPaymentUsd: config.maxPaymentUsd, budgetUsd: config.budgetUsd }).address;
    process.stderr.write(`x402check-mcp: paying from ${address} (max $${(config.maxPaymentUsd ?? DEFAULT_MAX_PAYMENT_USD).toFixed(3)} per check, budget $${(config.budgetUsd ?? DEFAULT_BUDGET_USD).toFixed(2)})\n`);
  } else {
    process.stderr.write("x402check-mcp: no X402CHECK_PAYER_KEY: checks are paid via x402 and will return not_verified until a payer is configured\n");
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

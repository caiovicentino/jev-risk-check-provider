#!/usr/bin/env node
// x402check MCP server over stdio. stdout carries MCP messages only: diagnostics go to stderr.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { configFromEnv, createX402CheckServer } from "./server.js";
import { VERSION } from "./version.js";

const HELP = `x402check-mcp ${VERSION}: MCP server (stdio) for x402check pre-payment risk checks.

Environment:
  X402CHECK_BASE_URL     API origin (default https://x402check.xyz)
  X402CHECK_CLIENT_ID    stable random id for this install: its own 25/day free allowance
  X402CHECK_ISSUER       trusted attestation issuer (default did:web:x402check.xyz)
  X402CHECK_TIMEOUT_MS   per API call (default 10000)

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
  const server = createX402CheckServer(configFromEnv(process.env));
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

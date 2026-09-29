// End-to-end: spawns the BUILT bin (dist/index.js, as `npx @x402check/mcp` would run it) and
// talks MCP over its stdin/stdout, with the API served by a local HTTP mock. `pretest` builds.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const BIN = fileURLToPath(new URL("../dist/index.js", import.meta.url));

test("the bin has a node shebang and answers --version / --help without starting a server", () => {
  assert.match(readFileSync(BIN, "utf8"), /^#!\/usr\/bin\/env node\n/);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string; bin: Record<string, string> };
  assert.deepEqual(pkg.bin, { "x402check-mcp": "dist/index.js" });
  assert.equal(spawnSync(process.execPath, [BIN, "--version"], { encoding: "utf8" }).stdout.trim(), pkg.version);
  assert.match(spawnSync(process.execPath, [BIN, "--help"], { encoding: "utf8" }).stdout, /X402CHECK_BASE_URL/);
});

test("stdio: tools are served over stdin/stdout, configured from the environment", async () => {
  const hits: Array<{ url: string; headers: IncomingHttpHeaders; body: string }> = [];
  const api = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
    req.on("end", () => {
      hits.push({ url: req.url ?? "", headers: req.headers, body });
      res.writeHead(422, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_request", field: "wallet" }));
    });
  });
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  const { port } = api.address() as AddressInfo;

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN],
    env: { X402CHECK_BASE_URL: `http://127.0.0.1:${port}`, X402CHECK_CLIENT_ID: "stdio-e2e" },
    stderr: "pipe",
  });
  const client = new Client({ name: "stdio-e2e", version: "0.0.0" });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["x402check_check", "x402check_methodology", "x402check_verify_attestation"]);
    const result = (await client.callTool({ name: "x402check_check", arguments: { wallet: "definitely-not-an-address" } })) as {
      content: Array<{ type: string; text: string }>;
      isError?: boolean;
    };
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? "", /^x402check: NOT VERIFIED\. STOP/);
    assert.match(result.content[0]?.text ?? "", /field "wallet"/);
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.url, "/v1/risk-check");
    assert.equal(hits[0]?.headers["x-risk-check-client"], "stdio-e2e");
    assert.equal(hits[0]?.headers["content-type"], "application/json");
    assert.deepEqual(JSON.parse(hits[0]?.body ?? ""), { wallet: "definitely-not-an-address" });
  } finally {
    await client.close();
    await new Promise<void>((resolve) => api.close(() => resolve()));
  }
});

test("an invalid configuration fails fast on stderr with a non-zero exit", () => {
  const cases: Array<[Record<string, string>, RegExp]> = [
    [{ X402CHECK_BASE_URL: "ftp://nope" }, /x402check-mcp: baseUrl must be http\(s\)/],
    [{ X402CHECK_ISSUER: "https://x402check.xyz" }, /x402check-mcp: issuer must be a did:web DID/],
    [{ X402CHECK_CLIENT_ID: "has spaces" }, /x402check-mcp: clientId must be/],
  ];
  for (const [env, message] of cases) {
    const run = spawnSync(process.execPath, [BIN], { encoding: "utf8", env: { ...process.env, ...env }, input: "" });
    assert.notEqual(run.status, 0, JSON.stringify(env));
    assert.equal(run.stdout, "", "stdout is reserved for MCP messages");
    assert.match(run.stderr, message);
  }
});

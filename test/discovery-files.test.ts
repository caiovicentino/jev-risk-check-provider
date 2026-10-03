// Discovery files agents ask for (Cloudflare analytics, 2026-10-03): /llms.txt, /.well-known/x402
// (x402scan's compatibility format) and /sitemap.xml, built from the same sources as /openapi.json,
// with HEAD support and the security headers. No A2A agent card: x402check is not an A2A agent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { openApi } from "../deploy/protected.js";
import { llmsTxt, wellKnownX402 } from "../deploy/discovery.js";
import { formatUsd, MICRO, networkPrice, SIMULATION_PRICE } from "../deploy/pricing.js";
import { CREDIT_CHECK_PRICE } from "../deploy/credits.js";
import type { WorkerEnv } from "../deploy/runtime.js";

// The Worker embeds its .bin feeds through wrangler's Data rule; under Node they load as bytes.
register(
  "data:text/javascript," +
    encodeURIComponent(`import { readFileSync } from "node:fs";
export async function load(url, context, next) {
  if (!url.endsWith(".bin")) return next(url, context);
  const b64 = readFileSync(new URL(url)).toString("base64");
  return { format: "module", shortCircuit: true, source: "export default Uint8Array.from(atob(" + JSON.stringify(b64) + "), (c) => c.charCodeAt(0)).buffer;" };
}`),
);
const { default: worker } = await import("../deploy/worker.js");
const env: WorkerEnv = { PROVIDER_HOST: "x402check.xyz", CREDITS: {} as never };
const get = (path: string, method = "GET") => worker.fetch(new Request(`https://x402check.xyz${path}`, { method }), env);
const plain = (usd: number) => formatUsd(Math.round(usd * MICRO)).slice(1);

test("/.well-known/x402 lists exactly the paid resources the OpenAPI document declares", async () => {
  const res = await get("/.well-known/x402");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/);
  const body = (await res.json()) as { version: number; resources: string[] };
  assert.equal(body.version, 1);
  const paid = Object.entries((openApi(env) as { paths: Record<string, { post?: Record<string, unknown> }> }).paths)
    .filter(([, item]) => item.post?.["x-payment-info"])
    .map(([path]) => `https://x402check.xyz${path}`);
  assert.deepEqual(body.resources, paid);
  assert.deepEqual(body.resources, ["https://x402check.xyz/v1/risk-check", "https://x402check.xyz/v1/risk-check/batch", "https://x402check.xyz/v1/credits"]);
  assert.deepEqual(wellKnownX402(openApi(env)).resources, body.resources);
});

test("/llms.txt states the live prices, routes and request fields", async () => {
  const res = await get("/llms.txt");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/markdown/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  const text = await res.text();
  assert.equal(text, llmsTxt(openApi(env)));
  assert.match(text, /^# x402check\n\n> /);
  for (const path of ["/v1/risk-check", "/v1/risk-check/batch", "/v1/credits"]) assert.ok(text.includes(`[POST ${path}](https://x402check.xyz${path})`), path);
  assert.ok(text.includes(`$${plain(networkPrice("eip155:8453"))} on Base`), "the Base per-call price");
  assert.ok(text.includes(`$${plain(CREDIT_CHECK_PRICE)} a check`), "the credits price");
  assert.ok(text.includes(`$${plain(SIMULATION_PRICE)} simulated`), "the simulated price");
  for (const field of ["wallet", "chain", "domain", "context", "aud", "interaction", "payment", "transaction", "screening", "authorization"]) assert.ok(text.includes(`\`${field}\``), field);
  assert.match(text, /`wallet` \(required\)/);
  assert.match(text, /no free tier/);
});

test("/sitemap.xml names the site; HEAD works on every discovery file; no A2A agent card is served", async () => {
  const res = await get("/sitemap.xml");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /application\/xml/);
  assert.match(await res.text(), /<loc>https:\/\/x402check\.xyz\/<\/loc>/);
  for (const path of ["/llms.txt", "/.well-known/x402", "/sitemap.xml"]) {
    const head = await get(path, "HEAD");
    assert.equal(head.status, 200, path);
    assert.equal(await head.text(), "", `${path}: HEAD has no body`);
    assert.ok(head.headers.get("cache-control"), path);
  }
  for (const path of ["/.well-known/agent.json", "/.well-known/agent-card.json"]) assert.equal((await get(path)).status, 404, path);
});

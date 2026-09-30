// x402 Bazaar discovery (deploy/discovery.ts): what catalogs such as Coinbase CDP's Bazaar
// read from our 402 challenge, and what a GET on a paid endpoint explains.
import { test } from "node:test";
import assert from "node:assert";
import { x402ResourceServer, type FacilitatorClient } from "@x402/core/server";
import { x402HTTPResourceServer, type PaymentOption, type RouteConfig } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { BATCH_DISCOVERY, REQUEST_EXAMPLE, RISK_CHECK_DISCOVERY, SERVICE_METADATA } from "../deploy/discovery.js";
import { paidRoutes, usageFor } from "../deploy/protected.js";
import { fetchAdapter } from "../deploy/http-util.js";
import { validateBatch, validateRequest } from "../src/validate.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";

test("the published examples are requests our own API accepts", () => {
  assert.equal(validateRequest(RISK_CHECK_DISCOVERY.bazaar.info.input.body).ok, true);
  assert.equal(validateBatch(BATCH_DISCOVERY.bazaar.info.input.body).ok, true);
  for (const path of ["/v1/risk-check", "/v1/risk-check/batch"]) {
    const usage = usageFor(path);
    const example = usage.example as Record<string, unknown>;
    assert.equal((path.endsWith("/batch") ? validateBatch(example) : validateRequest(example)).ok, true, path);
    assert.deepEqual(usage.pricing, { credits_usd: "0.001", per_call_from_usd: "0.0035", simulated_usd: "0.005", buy_credits: 'POST /v1/credits {"amount_usd": 1}' });
  }
  // The schema requires what the validator requires, and names every interaction type it accepts.
  assert.deepEqual(RISK_CHECK_DISCOVERY.bazaar.schema.properties.input.properties.body.required, ["wallet"]);
  assert.equal(validateRequest({ ...REQUEST_EXAMPLE, interaction: { type: "not_a_type" } }).ok, false);
});

test("paid routes carry the service metadata and, for checks, the Bazaar declaration", () => {
  const routes = paidRoutes({}) as Record<string, RouteConfig>;
  assert.deepEqual(Object.keys(routes), ["POST /v1/risk-check", "POST /v1/risk-check/batch"], "no credits route without the ledger");
  for (const [key, route] of Object.entries(routes)) {
    assert.equal(route.serviceName, "x402check", key);
    assert.deepEqual(route.tags, [...SERVICE_METADATA.tags]);
    assert.ok(route.tags && route.tags.length <= 5 && route.serviceName && route.serviceName.length <= 32, "catalog limits");
    assert.equal(route.iconUrl, "https://x402check.xyz/icon.png");
    const bazaar = (route.extensions as { bazaar: { info: { input: Record<string, unknown> } } }).bazaar;
    assert.deepEqual([bazaar.info.input.type, bazaar.info.input.method, bazaar.info.input.bodyType], ["http", "POST", "json"], key);
  }
  const withCredits = paidRoutes({ CREDITS: {} as never }) as Record<string, RouteConfig>;
  assert.equal(withCredits["POST /v1/credits"]?.extensions, undefined, "a credit pack is not listed as a service");
});

test("the real x402 402 challenge carries the Bazaar extension and the service metadata", async () => {
  const facilitator: FacilitatorClient = {
    verify: async () => ({ isValid: true }) as never,
    settle: async () => ({ success: true }) as never,
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }], extensions: ["bazaar"], signers: {} }) as never,
  };
  const route = (paidRoutes({}) as Record<string, RouteConfig>)["POST /v1/risk-check"] as RouteConfig;
  const baseOnly = { ...route, accepts: (route.accepts as PaymentOption[]).filter((a) => a.network === "eip155:8453") };
  const server = new x402ResourceServer([facilitator]).register("eip155:*", new ExactEvmScheme());
  const http = new x402HTTPResourceServer(server, { "POST /v1/risk-check": baseOnly });
  await http.initialize();
  const request = new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(REQUEST_EXAMPLE) });
  const result = await http.processHTTPRequest({ adapter: fetchAdapter(request, REQUEST_EXAMPLE), path: "/v1/risk-check", method: "POST" });
  assert.equal(result.type, "payment-error");
  const header = result.type === "payment-error" ? (result.response.headers["PAYMENT-REQUIRED"] ?? result.response.headers["payment-required"]) : undefined;
  assert.ok(header, "a PAYMENT-REQUIRED challenge");
  const challenge = JSON.parse(Buffer.from(header as string, "base64").toString("utf8")) as {
    resource: { url: string; serviceName?: string; tags?: string[]; iconUrl?: string; description: string };
    extensions?: { bazaar?: { info: { input: { method: string; body: unknown } } } };
    accepts: Array<{ amount: string }>;
  };
  assert.equal(challenge.resource.serviceName, "x402check");
  assert.equal(challenge.resource.iconUrl, "https://x402check.xyz/icon.png");
  assert.match(challenge.resource.description, /^Check a counterparty before paying/);
  assert.equal(challenge.extensions?.bazaar?.info.input.method, "POST");
  assert.deepEqual(challenge.extensions?.bazaar?.info.input.body, REQUEST_EXAMPLE);
  assert.equal(challenge.accepts[0]?.amount, "3500", "Base per-call price");
});

test("the service icon is served", async () => {
  const handler = createHandler({ provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev: null }) });
  const res = await handler(new Request("https://x402check.xyz/icon.png"));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Type"), "image/png");
  const bytes = new Uint8Array(await res.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 4)], [0x89, 0x50, 0x4e, 0x47], "PNG signature");
});

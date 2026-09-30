// x402 Bazaar discovery (deploy/discovery.ts): what catalogs such as Coinbase CDP's Bazaar
// read from our 402 challenge, and what a GET on a paid endpoint explains.
import { test } from "node:test";
import assert from "node:assert";
import { x402ResourceServer, type FacilitatorClient } from "@x402/core/server";
import { x402HTTPResourceServer, type PaymentOption, type RouteConfig } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { BATCH_DISCOVERY, REQUEST_EXAMPLE, RISK_CHECK_DISCOVERY, SERVICE_METADATA } from "../deploy/discovery.js";
import { handleProtected, openApi, paidRoutes, usageFor, type Stack } from "../deploy/protected.js";
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
    assert.deepEqual(usage.pricing, { credits_usd: "0.001", per_call_from_usd: "0.001", per_call_base_usd: "0.0035", simulated_usd: "0.005", buy_credits: 'POST /v1/credits {"amount_usd": 1}' });
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

test("the service icon and the favicon are served", async () => {
  const handler = createHandler({ provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev: null }) });
  const res = await handler(new Request("https://x402check.xyz/icon.png"));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Type"), "image/png");
  const bytes = new Uint8Array(await res.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 4)], [0x89, 0x50, 0x4e, 0x47], "PNG signature");
  const ico = await handler(new Request("https://x402check.xyz/favicon.ico"));
  assert.equal(ico.headers.get("Content-Type"), "image/x-icon");
  assert.deepEqual([...new Uint8Array(await ico.arrayBuffer()).slice(0, 4)], [0, 0, 1, 0], "ICO header");
});

test("a discovery probe (unpaid POST, no body) gets the 402 for one item; a paid or authenticated empty body gets 422", async () => {
  const priced: string[] = [];
  const stack = {
    deps: { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev: null }) },
    http: {
      processHTTPRequest: async (ctx: { path: string; adapter: { getBody?: () => unknown }; paymentHeader?: string }) => {
        priced.push(`${ctx.path} ${JSON.stringify(ctx.adapter.getBody?.())}`);
        return ctx.paymentHeader ? { type: "payment-verified" } : { type: "payment-error", response: { status: 402, headers: { "PAYMENT-REQUIRED": "challenge" }, body: {} } };
      },
    },
  } as unknown as Stack;
  const evaluated: string[] = [];
  const serve = async (req: Request) => {
    evaluated.push(req.url);
    return new Response("{}", { status: 200 });
  };
  const post = (path: string, headers: Record<string, string> = {}) => new Request(`https://x402check.xyz${path}`, { method: "POST", headers: { Accept: "application/json", ...headers } });
  for (const path of ["/v1/risk-check", "/v1/risk-check/batch"]) {
    const res = await handleProtected(post(path), {}, stack, serve);
    assert.equal(res.status, 402, path);
    assert.equal(res.headers.get("PAYMENT-REQUIRED"), "challenge");
  }
  assert.deepEqual(priced, ["/v1/risk-check {}", "/v1/risk-check/batch {}"], "priced as one item");
  assert.equal((await handleProtected(post("/v1/risk-check", { "PAYMENT-SIGNATURE": "sig" }), {}, stack, serve)).status, 422, "a payment for nothing is never settled");
  assert.equal((await handleProtected(post("/v1/risk-check", { Authorization: "Bearer x402c_x" }), {}, stack, serve)).status, 422);
  assert.deepEqual(evaluated, [], "nothing unpaid or empty is evaluated");
});

test("the OpenAPI discovery document prices every paid operation and matches the validator", () => {
  const doc = openApi({}) as { openapi: string; info: Record<string, unknown>; paths: Record<string, { post: { "x-payment-info": { price: Record<string, string>; protocols: unknown[] }; requestBody: { content: { "application/json": { schema: unknown; example: unknown } } }; responses: Record<string, unknown> } }> };
  assert.equal(doc.openapi, "3.1.0");
  assert.match(String(doc.info["x-guidance"]), /POST \/v1\/risk-check/);
  const price = (p: string) => doc.paths[p]?.post["x-payment-info"].price;
  assert.deepEqual(price("/v1/risk-check"), { mode: "dynamic", currency: "USD", min: "0.001", max: "0.009" });
  assert.deepEqual(price("/v1/risk-check/batch"), { mode: "dynamic", currency: "USD", min: "0.001", max: "0.225" });
  assert.deepEqual(price("/v1/credits"), { mode: "dynamic", currency: "USD", min: "0.10", max: "100.00" });
  for (const [p, op] of Object.entries(doc.paths)) {
    assert.deepEqual(op.post["x-payment-info"].protocols, [{ x402: {} }], p);
    assert.ok(op.post.responses["402"], `${p}: declares its 402`);
  }
  assert.equal(validateRequest(doc.paths["/v1/risk-check"]?.post.requestBody.content["application/json"].example).ok, true);
  assert.equal(validateBatch(doc.paths["/v1/risk-check/batch"]?.post.requestBody.content["application/json"].example).ok, true);
});

// Fixes from the 2026-10-16 production reviews (payments, black box): rate-limit keys, request
// bodies that meant different things to different parsers, lengths counted as the published
// schemas count them, and 405 for a known resource asked with the wrong method.
import { test } from "node:test";
import assert from "node:assert/strict";
import { rateKey } from "../deploy/http-util.js";
import { repeatedKey, strictUtf8, validateRequest } from "../src/validate.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { handleProtected, type Stack } from "../deploy/protected.js";

const req = (headers: Record<string, string>) => new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers });

test("rate-limit keys: a Worker on another zone by its zone, IPv6 by its /64, IPv4 by its address", () => {
  // Cloudflare gives every Worker on another zone this one address: they must not share a bucket.
  assert.equal(rateKey(req({ "CF-Connecting-IP": "2a06:98c0:3600::103", "CF-Worker": "Agent-One.example" })), "worker:agent-one.example");
  assert.notEqual(rateKey(req({ "CF-Connecting-IP": "2a06:98c0:3600::103", "CF-Worker": "agent-two.example" })), rateKey(req({ "CF-Connecting-IP": "2a06:98c0:3600::103", "CF-Worker": "agent-one.example" })));
  // One subscriber's /64 is one bucket, however its addresses are spelled.
  assert.equal(rateKey(req({ "CF-Connecting-IP": "2001:db8:aa:1::1" })), "2001:db8:aa:1::/64");
  assert.equal(rateKey(req({ "CF-Connecting-IP": "2001:0db8:00aa:0001:ffff:ffff:ffff:ffff" })), "2001:db8:aa:1::/64");
  assert.notEqual(rateKey(req({ "CF-Connecting-IP": "2001:db8:aa:2::1" })), "2001:db8:aa:1::/64");
  assert.equal(rateKey(req({ "CF-Connecting-IP": "::ffff:203.0.113.7" })), "203.0.113.7");
  assert.equal(rateKey(req({ "CF-Connecting-IP": "203.0.113.7" })), "203.0.113.7");
});

test("bodies: invalid UTF-8 and a key that repeats are refused, never read one way here and another elsewhere", async () => {
  assert.equal(strictUtf8(new Uint8Array([0x61, 0xff, 0xfe, 0x62])), null);
  assert.equal(strictUtf8(new TextEncoder().encode('{"a":"é😀"}')), '{"a":"é😀"}');
  assert.equal(repeatedKey('{"wallet":"x","wallet":"y"}'), true);
  assert.equal(repeatedKey('{"w\\u0061llet":"x","wallet":"y"}'), true, "compared after unescaping");
  assert.equal(repeatedKey('{"a":{"wallet":1},"b":{"wallet":2},"wallet":3}'), false, "the same key in different objects");
  assert.equal(repeatedKey('{"requests":[{"wallet":1},{"wallet":2}]}'), false);
  assert.equal(repeatedKey('{"context":"a \\"quoted\\" {brace} , ] [","x":1}'), false, "strings may hold any of the structural characters");
  // End to end: with a credential, a refused body is a 422 before any payment work.
  const stack = { deps: {} as never, keyStatus: { ok: true, kid: "k", thumbprint: "t" }, http: { processHTTPRequest: async () => assert.fail("never reached") } } as unknown as Stack;
  const token = `Bearer x402c_${"a".repeat(43)}`;
  const send = (body: string | Uint8Array) => handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "content-type": "application/json", Authorization: token }, body }), {}, stack, async () => new Response("unreachable"));
  const badUtf8 = await send(new Uint8Array([...new TextEncoder().encode('{"wallet":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","context":"abc'), 0xff, ...new TextEncoder().encode('"}')]));
  assert.equal(badUtf8.status, 422);
  const twice = await send('{"wallet":"not-an-address","wallet":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"}');
  assert.deepEqual([twice.status, ((await twice.json()) as { field: string }).field], [422, "body"]);
});

test("lengths count code points, as the published JSON Schema maxLength does", () => {
  const W = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  assert.equal(validateRequest({ wallet: W, context: "😀".repeat(4096) }).ok, true, "4,096 emoji: 8,192 UTF-16 units, 4,096 characters");
  assert.deepEqual(validateRequest({ wallet: W, context: "😀".repeat(4097) }), { ok: false, field: "context" });
});

test("a known resource asked with another method is 405 with Allow, not 404", async () => {
  const handler = createHandler({ provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev: null as never }) });
  for (const [method, path] of [["POST", "/openapi.json"], ["DELETE", "/.well-known/jwks.json"], ["POST", "/"], ["PUT", "/sitemap.xml"]] as const) {
    const res = await handler(new Request(`https://x402check.xyz${path}`, { method }));
    assert.equal(res.status, 405, `${method} ${path}`);
    assert.equal(res.headers.get("allow"), "GET, HEAD");
  }
  assert.equal((await handler(new Request("https://x402check.xyz/nowhere", { method: "POST" }))).status, 404);
});

test("discovery waits for a cold isolate's first routing table, never longer than its bound (a hung facilitator)", async () => {
  const { routingKnown } = await import("../deploy/protected.js");
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
    String(input instanceof Request ? input.url : input).includes("hung-facilitator.example") ? new Promise<Response>(() => undefined) : realFetch(input, init)) as typeof fetch;
  try {
    const started = Date.now();
    await routingKnown({ X402_FACILITATOR_URL_PAYAI: "https://hung-facilitator.example/payai", X402_FACILITATOR_URL_MAINNET: "https://hung-facilitator.example/dexter" }, 300);
    assert.ok(Date.now() - started < 1500, `bounded: ${Date.now() - started} ms`);
  } finally {
    globalThis.fetch = realFetch;
  }
});

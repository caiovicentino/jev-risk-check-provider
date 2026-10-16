// A facilitator that hangs or fails while the payment stack is built must not turn the 402
// challenge into a 500 (two monitors got one on 2026-10-15): routing leaves its networks out, the
// stack offers what the others serve, and anything that still fails is a 503 with Retry-After.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ensureStack, handleProtected, paymentRouting } from "../deploy/protected.js";
import type { WorkerEnv } from "../deploy/runtime.js";

const kind = (network: string) => ({ x402Version: 2, scheme: "exact", network, extra: {} });
// A development host: the stack signs with an ephemeral key (production refuses to run without its own).
const env: WorkerEnv = { PROVIDER_HOST: "localhost:8799", X402_FACILITATOR_URL_PAYAI: "https://payai.test", X402_FACILITATOR_URL_MAINNET: "https://dexter.test" };
let dexter: "up" | "hang" = "hang";
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  const reply = (body: unknown) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  if (url.startsWith("https://payai.test/supported")) return reply({ kinds: [kind("eip155:8453"), kind("eip155:1329")], extensions: [], signers: {} });
  if (url.startsWith("https://payai.test/pricing")) return reply({ rates: [{ network: "eip155:8453", scheme: "exact", transferMethod: "eip3009", usd: "0.002" }, { network: "eip155:1329", scheme: "exact", transferMethod: "eip3009", usd: "0.0006" }] });
  if (url.startsWith("https://dexter.test/supported")) {
    if (dexter === "hang") return new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    return reply({ kinds: [kind("eip155:143")], extensions: [], signers: {} });
  }
  return realFetch(input, init);
}) as typeof fetch;

const unpaid = () => new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "content-type": "application/json" }, body: "" });
const networks = (res: Response) => (JSON.parse(Buffer.from(res.headers.get("payment-required") ?? "", "base64").toString("utf8")) as { accepts: Array<{ network: string }> }).accepts.map((a) => a.network);

test("a hung facilitator leaves the challenge, never breaks it", async () => {
  const t = Date.now();
  const stack = await ensureStack(env);
  assert.ok(Date.now() - t < 7000, `built in ${Date.now() - t} ms`);
  const res = await handleProtected(unpaid(), env, stack, async () => new Response("unreachable"));
  assert.equal(res.status, 402);
  assert.deepEqual(networks(res), ["eip155:8453", "eip155:1329"], "Base and Sei through PayAI; Monad, served only by the hung facilitator, is left out");
  const routes = await paymentRouting(env);
  assert.deepEqual(routes.filter((r) => !r.offered).map((r) => [r.network, r.reason]).find(([n]) => n === "eip155:143"), ["eip155:143", "no_facilitator"]);
});

test("a stack that cannot read payments answers 503 with Retry-After, never 500", async () => {
  const broken = { deps: {} as never, keyStatus: { ok: true, kid: "k", thumbprint: "t" }, http: { processHTTPRequest: async () => { throw new Error("Facilitator does not support exact on eip155:1329"); } } } as never;
  for (const body of ["", JSON.stringify({ wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" })]) {
    const res = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "content-type": "application/json" }, body }), env, broken, async () => new Response("unreachable"));
    assert.equal(res.status, 503, body || "(no body)");
    assert.equal(res.headers.get("retry-after"), "10");
    assert.equal(((await res.json()) as { error: string }).error, "payment_unavailable");
  }
});

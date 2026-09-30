// Regression tests for the 2026-09-30 audit's paid-flow findings: single use of a payment
// (pay-1, pay-3), SDN-listed payers (critic-5), the attestation key self-check (mc-2), routing
// around a facilitator that is down and the Monad transfer method (pay-2, pay-9), a credit pack
// whose ledger write fails after settlement (pay-5), the simulation surcharge (pay-7), and the
// Worker's HTTPS, security headers and security.txt (prod-1, prod-4, prod-6).
import { test } from "node:test";
import assert from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { CreditLedger, handleCredits, retryPendingCredits } from "../deploy/credits.js";
import { buildAccepts, handleProtected, loadKeyPair, type PaymentRoute, type Stack } from "../deploy/protected.js";
import { PaymentClaim, paymentId } from "../deploy/payment-claims.js";
import type { DurableObjectNamespace, DurableObjectState, KVNamespace, WorkerEnv } from "../deploy/runtime.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { OFAC_SDN_ADDRESSES } from "../src/data/ofac-sdn.js";
import type { JevLike } from "../src/jev.js";
import type { Simulator } from "../src/simulation.js";
import type { Answer } from "../src/types.js";
import type { HTTPRequestContext } from "@x402/core/http";
import { register } from "node:module";

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

const USER = "0x1111111111111111111111111111111111111111";
const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const ANSWERS: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const jev: JevLike = { systemOne: async () => ({ answers: ANSWERS, usage: { inputTokens: 1, outputTokens: 0 } }) };
const payment = (from: string, nonce = "0x01") => btoa(JSON.stringify({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { from, nonce } } }));

function memoryState(): DurableObjectState {
  const data = new Map<string, unknown>();
  return {
    storage: {
      get: async <T>(key: string) => data.get(key) as T | undefined,
      put: (async (a: string | Record<string, unknown>, b?: unknown) => {
        if (typeof a === "string") data.set(a, b);
        else for (const [k, v] of Object.entries(a)) data.set(k, v);
      }) as DurableObjectState["storage"]["put"],
      delete: async (key: string) => data.delete(key),
      deleteAll: async () => data.clear(),
      setAlarm: async () => undefined,
    },
  };
}

/** An in-memory Durable Object namespace running a real class; `down` makes every call fail. */
function namespace<T extends { fetch(r: Request): Promise<Response> }>(make: (s: DurableObjectState) => T, down = { value: false }): DurableObjectNamespace {
  const objects = new Map<string, T>();
  return {
    idFromName: (name: string) => ({ toString: () => name }),
    get: (id) => {
      const name = id.toString();
      let obj = objects.get(name);
      if (!obj) objects.set(name, (obj = make(memoryState())));
      return {
        fetch: async (input: string | Request, init?: RequestInit) => {
          if (down.value) throw new Error("durable object unavailable");
          return (obj as T).fetch(new Request(input, init));
        },
      };
    },
  };
}

function memoryKv(): KVNamespace & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    get: (async (key: string) => data.get(key) ?? null) as KVNamespace["get"],
    put: async (key: string, value: string) => void data.set(key, value),
    delete: async (key: string) => void data.delete(key),
    list: async ({ prefix }: { prefix: string }) => ({ keys: [...data.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }),
  };
}

/** A payment stack that verifies whatever v2 payment it is given and settles per `settle`. */
function stack(from: string, settle: { ok: boolean; tx: string; settled: number }): Stack {
  const deps = { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev }) };
  const http = {
    processHTTPRequest: async (ctx: HTTPRequestContext) => {
      if (!ctx.paymentHeader) return { type: "payment-error", response: { status: 402, headers: {}, body: { error: "payment_required" } } };
      return { type: "payment-verified", paymentPayload: { payload: { authorization: { from } } }, paymentRequirements: {} };
    },
    processSettlement: async () => {
      settle.settled++;
      return settle.ok ? { success: true, headers: { "PAYMENT-RESPONSE": btoa(JSON.stringify({ success: true, transaction: settle.tx, network: "eip155:8453" })) } } : { success: false, errorReason: "nonce_used", headers: {} };
    },
  };
  return { deps, http, keyStatus: { ok: true, kid: "jev-attest-v1", thumbprint: null } } as unknown as Stack;
}

const req = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`https://x402check.xyz${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });

test("a payment is used once: concurrent copies get a 409; a payment that did not settle can be retried", async () => {
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s)) };
  const settle = { ok: true, tx: "0xaaa", settled: 0 };
  const s = stack(USER, settle);
  const header = payment(USER, "0x10");
  const send = () => handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header }), env, s, (r) => createHandler(s.deps)(r));
  const statuses = (await Promise.all([send(), send(), send()])).map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 409, 409]);
  assert.equal(settle.settled, 1, "settled once");

  const failing = { ok: false, tx: "0xbbb", settled: 0 };
  const f = stack(USER, failing);
  const other = payment(USER, "0x11");
  const first = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": other }), env, f, (r) => createHandler(f.deps)(r));
  assert.equal(first.status, 402);
  failing.ok = true;
  const retry = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": other }), env, f, (r) => createHandler(f.deps)(r));
  assert.equal(retry.status, 200, "a claim is released when nothing settled");
  assert.notEqual(await paymentId(header), await paymentId(other));
});

test("claims unreachable: no evaluation and no charge (503); a credit pack is bought once", async () => {
  const down = { value: true };
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s), down) };
  const settle = { ok: true, tx: "0xccc", settled: 0 };
  const s = stack(USER, settle);
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, "0x12") }), env, s, (r) => createHandler(s.deps)(r));
  assert.equal(res.status, 503);
  assert.equal(settle.settled, 0);

  down.value = false;
  const credits: WorkerEnv = { ...env, CREDITS: namespace((st) => new CreditLedger(st)) };
  const header = payment(USER, "0x13");
  const buys = await Promise.all([1, 2].map(() => handleCredits(req("/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": header }), credits, stack(USER, { ok: true, tx: "0xddd", settled: 0 }))));
  assert.deepEqual(buys.map((r) => r.status).sort(), [200, 409], "one payment mints one token");
});

test("an SDN-listed payer is refused before any evaluation or settlement", async () => {
  const listed = OFAC_SDN_ADDRESSES.find(([a]) => /^0x[0-9a-fA-F]{40}$/.test(a))?.[0] as string;
  assert.ok(listed);
  const settle = { ok: true, tx: "0xeee", settled: 0 };
  const s = stack(listed, settle);
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(listed) }), {}, s, (r) => createHandler(s.deps)(r));
  assert.equal(res.status, 403);
  assert.equal(((await res.json()) as { error: string }).error, "payer_sanctioned");
  assert.equal(settle.settled, 0);
});

test("the attestation key is checked at load: missing on a production host, or a private/public mismatch, is reported", () => {
  const pair = () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    return { pem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(), jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid: "jev-attest-v2", alg: "ES256", use: "sig" } };
  };
  const a = pair();
  const b = pair();
  const good = loadKeyPair({ JEV_ATTEST_PRIVATE_KEY: a.pem, JEV_ATTEST_PUBLIC_JWK: JSON.stringify(a.jwk) });
  assert.equal(good.status.ok, true);
  assert.match(good.status.thumbprint ?? "", /^[A-Za-z0-9_-]{43}$/);
  const escaped = loadKeyPair({ JEV_ATTEST_PRIVATE_KEY: a.pem.replace(/\n/g, "\\n"), JEV_ATTEST_PUBLIC_JWK: JSON.stringify(a.jwk) });
  assert.equal(escaped.status.ok, true, "a PEM with escaped newlines is accepted");
  const mismatch = loadKeyPair({ JEV_ATTEST_PRIVATE_KEY: a.pem, JEV_ATTEST_PUBLIC_JWK: JSON.stringify(b.jwk) });
  assert.equal(mismatch.status.ok, false);
  assert.match(mismatch.status.reason ?? "", /does not match/);
  assert.equal(loadKeyPair({}).status.ok, false, "production without secrets");
  assert.equal(loadKeyPair({ PROVIDER_HOST: "localhost:8799" }).status.ok, true, "local development may use an ephemeral key");
});

test("a paid route refuses all work (no charge) while the key cannot sign verifiable attestations", async () => {
  const s = { ...stack(USER, { ok: true, tx: "0x1", settled: 0 }), keyStatus: { ok: false, kid: "k", thumbprint: null, reason: "mismatch" } } as Stack;
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER) }), {}, s, (r) => createHandler(s.deps)(r));
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "attestation_key_unavailable");
});

test("routing: a network with no live facilitator leaves the challenge; a Permit2-only route says so", () => {
  const route = (network: string, facilitator: string | null, method: string | null): PaymentRoute => ({ network, price_usd: 0.001, facilitator, transfer_method: method, fee_usd: 0, floor_usd: null, below_floor: false, margin_usd: 0, margin_pct: 0 });
  const routes = [route("eip155:8453", "cdp", "eip3009"), route("eip155:143", "dexter", "permit2"), route("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", null, null)];
  const accepts = buildAccepts({}, undefined, routes);
  assert.deepEqual(accepts.map((a) => a.network), ["eip155:8453", "eip155:143"]);
  assert.deepEqual(accepts.find((a) => a.network === "eip155:143")?.extra, { assetTransferMethod: "permit2" });
  assert.equal(buildAccepts({}).length, 7, "without a routing table every network is offered");
});

test("a pack whose ledger write fails after settlement: 202 with the token, credited later by the cron", async () => {
  const ledgerDown = { value: true };
  const kv = memoryKv();
  const env: WorkerEnv = { CREDITS: namespace((s) => new CreditLedger(s), ledgerDown), RATE: kv };
  const res = await handleCredits(req("/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": payment(USER, "0x20") }), env, stack(USER, { ok: true, tx: "0xfff", settled: 0 }));
  assert.equal(res.status, 202);
  const body = (await res.json()) as { token?: string; status?: string };
  assert.match(body.token ?? "", /^x402c_/);
  assert.equal(body.status, "pending");
  assert.ok(res.headers.get("PAYMENT-RESPONSE"), "the receipt is kept");
  assert.equal([...kv.data.keys()].filter((k) => k.startsWith("pc:")).length, 1);
  assert.ok(![...kv.data.values()].some((v) => v.includes(body.token as string)), "the queue never stores the token");
  ledgerDown.value = false;
  assert.equal(await retryPendingCredits(env), 1);
  const balance = await handleCredits(new Request("https://x402check.xyz/v1/credits", { headers: { Authorization: `Bearer ${body.token}` } }), env, stack(USER, { ok: true, tx: "0x0", settled: 0 }));
  assert.equal(((await balance.json()) as { balance_usd: string }).balance_usd, "$1.00");
});

test("credits: the simulation surcharge is charged only when the simulation ran", async () => {
  const env: WorkerEnv = { CREDITS: namespace((s) => new CreditLedger(s)) };
  const bought = await handleCredits(req("/v1/credits", { amount_usd: 0.1 }, { "PAYMENT-SIGNATURE": payment(USER, "0x30") }), env, stack(USER, { ok: true, tx: "0x30", settled: 0 }));
  const { token } = (await bought.json()) as { token: string };
  const spend = async (simulator: Simulator | null) => {
    const deps = { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, simulator }) };
    const s = { ...stack(USER, { ok: true, tx: "0x0", settled: 0 }), deps } as Stack;
    const body = { wallet: USER, chain: "base", transaction: { from: USER, to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" } };
    const res = await handleProtected(req("/v1/risk-check", body, { Authorization: `Bearer ${token}` }), env, s, (r) => createHandler(s.deps)(r));
    return [res.status, res.headers.get("X-Credits-Charged"), res.headers.get("X-Credits-Balance")];
  };
  assert.deepEqual(await spend(async () => ({ status: "unavailable" })), [200, "$0.001", "$0.099"], "not simulated: a plain check's price");
  assert.deepEqual(await spend(async () => ({ status: "ok", network: "eip155:8453", outflows: [], inflows: [], approvals: [], findings: [] })), [200, "$0.005", "$0.094"]);
});

test("the Worker: HTTPS only, security headers everywhere, a CSP on the site, security.txt, key health in /healthz", async () => {
  const env: WorkerEnv = { PROVIDER_HOST: "x402check.xyz" };
  const page = await worker.fetch(new Request("http://x402check.xyz/", { headers: { Accept: "text/html" } }), env);
  assert.equal(page.status, 301);
  assert.equal(page.headers.get("Location"), "https://x402check.xyz/");
  const api = await worker.fetch(new Request("http://x402check.xyz/v1/risk-check", { method: "POST", body: "{}", headers: { Authorization: "Bearer x402c_secret" } }), env);
  assert.equal(api.status, 403);
  const site = await worker.fetch(new Request("https://x402check.xyz/", { headers: { Accept: "text/html" } }), env);
  assert.equal(site.status, 200);
  assert.match(site.headers.get("Content-Security-Policy") ?? "", /default-src 'none'; script-src 'sha256-[A-Za-z0-9+/=]+'/);
  assert.equal(site.headers.get("X-Frame-Options"), "DENY");
  assert.equal(site.headers.get("X-Content-Type-Options"), "nosniff");
  assert.match(site.headers.get("Strict-Transport-Security") ?? "", /max-age=31536000/);
  const txt = await worker.fetch(new Request("https://x402check.xyz/.well-known/security.txt"), env);
  assert.match(await txt.text(), /^Contact: https:\/\/github\.com\/caiovicentino\/jev-risk-check-provider\/security\/advisories\/new/m);
  const health = (await (await worker.fetch(new Request("https://x402check.xyz/healthz"), env)).json()) as { ok: boolean; attestation_key: string };
  assert.deepEqual([health.ok, health.attestation_key], [false, "misconfigured"], "no attestation secrets on a production host");
});

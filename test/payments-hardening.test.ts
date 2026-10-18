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
import { claimPayment, KEPT_MAX_BYTES, keptVerdict, PaymentClaim, paymentIdentity, requestFingerprint } from "../deploy/payment-claims.js";
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
const inAMinute = () => String(Math.floor(Date.now() / 1000) + 300);
const payment = (from: string, nonce = "0x01", validBefore = inAMinute()) => btoa(JSON.stringify({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { from, nonce, validBefore } } }));

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

/**
 * An in-memory Durable Object namespace running a real class; `down` makes every call fail. Calls
 * to one object run one at a time, as a Durable Object's input gate delivers them.
 */
function namespace<T extends { fetch(r: Request): Promise<Response> }>(make: (s: DurableObjectState) => T, down = { value: false }): DurableObjectNamespace {
  const objects = new Map<string, { obj: T; queue: Promise<unknown> }>();
  return {
    idFromName: (name: string) => ({ toString: () => name }),
    get: (id) => {
      const name = id.toString();
      let entry = objects.get(name);
      if (!entry) objects.set(name, (entry = { obj: make(memoryState()), queue: Promise.resolve() }));
      const e = entry;
      return {
        fetch: async (input: string | Request, init?: RequestInit) => {
          if (down.value) throw new Error("durable object unavailable");
          const run = e.queue.then(() => e.obj.fetch(new Request(input, init)));
          e.queue = run.catch(() => undefined);
          return run;
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
    // Like x402 core, the payment is read through the adapter (which hands over only v2 payments).
    processHTTPRequest: async (ctx: HTTPRequestContext) => {
      const header = ctx.adapter.getHeader("PAYMENT-SIGNATURE") ?? ctx.adapter.getHeader("X-PAYMENT");
      if (!header) return { type: "payment-error", response: { status: 402, headers: { "PAYMENT-REQUIRED": "challenge" }, body: { error: "payment_required" } } };
      const decoded = JSON.parse(atob(header)) as { payload?: { authorization?: { from?: string } } };
      return { type: "payment-verified", paymentPayload: { ...decoded, payload: { ...decoded.payload, authorization: { ...decoded.payload?.authorization, from: decoded.payload?.authorization?.from ?? from } } }, paymentRequirements: {} };
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
  const decode = (h: string) => JSON.parse(atob(h)) as unknown;
  assert.notEqual(await paymentIdentity(decode(header)), await paymentIdentity(decode(other)));
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
  const privateJwk = { ...a.jwk, d: "c2VjcmV0" };
  const pasted = loadKeyPair({ JEV_ATTEST_PRIVATE_KEY: a.pem, JEV_ATTEST_PUBLIC_JWK: JSON.stringify(privateJwk) });
  assert.equal(pasted.status.ok, false);
  assert.match(pasted.status.reason ?? "", /private key material/);
  assert.equal("d" in pasted.keyPair.publicJwk, false, "never kept for publication");
  assert.equal(loadKeyPair({ PROVIDER_HOST: "localhost:8799" }).status.ok, true, "local development may use an ephemeral key");
});

test("a paid route refuses all work (no charge) while the key cannot sign verifiable attestations", async () => {
  const s = { ...stack(USER, { ok: true, tx: "0x1", settled: 0 }), keyStatus: { ok: false, kid: "k", thumbprint: null, reason: "mismatch" } } as Stack;
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER) }), {}, s, (r) => createHandler(s.deps)(r));
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "attestation_key_unavailable");
});

test("routing: a network with no live facilitator leaves the challenge; a Permit2-only route says so", () => {
  const route = (network: string, facilitator: string | null, method: string | null): PaymentRoute => ({ network, price_usd: 0.001, facilitator, transfer_method: method, fee_usd: 0, floor_usd: null, below_floor: false, margin_usd: 0.00093, margin_pct: 93, offered: facilitator !== null, ...(facilitator ? {} : { reason: "no_facilitator" as const }) });
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

// The 2026-10-02 evaluation: single use by what the payer signed (F1), only v2 payments reach
// verification (F2), payments that cannot settle are not evaluated for free (F3), a settlement
// transaction pays once, and every unpaid request gets the challenge.
const evaluate = (s: Stack, calls = { n: 0 }, delayMs = 0) => async (r: Request) => {
  calls.n++;
  if (delayMs) await new Promise((ok) => setTimeout(ok, delayMs));
  return createHandler(s.deps)(r);
};
const claimsEnv = (): WorkerEnv => ({ PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)) });
const encode = (o: unknown) => btoa(JSON.stringify(o));

test("F1: one authorization re-encoded (key order, hex case, extra field, checksum) is one payment", async () => {
  const validBefore = inAMinute();
  const auth = { from: USER, to: "0x2222222222222222222222222222222222222222", value: "3500", validAfter: "0", validBefore, nonce: "0xabcdef" };
  const variants = [
    encode({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: auth } }),
    encode({ payload: { authorization: { nonce: "0xABCDEF", validBefore, validAfter: "0", value: "3500", to: auth.to, from: USER }, signature: "0x01" }, accepted: { network: "eip155:8453", scheme: "exact" }, x402Version: 2 }),
    encode({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { ...auth, from: USER.toUpperCase().replace("0X", "0x") }, padding: "x" } }),
  ];
  const ids = new Set(await Promise.all(variants.map((v) => paymentIdentity(JSON.parse(atob(v))))));
  assert.equal(ids.size, 1, "one identity");
  const env = claimsEnv();
  const settle = { ok: true, tx: "0xf1", settled: 0 };
  const s = stack(USER, settle);
  const calls = { n: 0 };
  const statuses = (await Promise.all(variants.map((v) => handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": v }), env, s, evaluate(s, calls, 20))))).map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 409, 409]);
  assert.deepEqual([calls.n, settle.settled], [1, 1], "evaluated and settled once");
});

test("F1: a Solana payment is identified by its message bytes, whatever its signatures or base64 spelling", async () => {
  const message = Uint8Array.from({ length: 120 }, (_, i) => (i * 7) % 256);
  const wire = (sigByte: number) => {
    const bytes = new Uint8Array(1 + 64 + message.length);
    bytes[0] = 1;
    bytes.fill(sigByte, 1, 65);
    bytes.set(message, 65);
    return Buffer.from(bytes).toString("base64");
  };
  const pp = (tx: string) => ({ accepted: { network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }, payload: { transaction: tx } });
  const a = await paymentIdentity(pp(wire(1)));
  assert.ok(a);
  assert.equal(await paymentIdentity(pp(wire(2))), a, "other signature bytes");
  assert.equal(await paymentIdentity(pp(wire(1).replace(/=+$/, ""))), a, "no padding");
  assert.equal(await paymentIdentity({ payload: { foo: 1 } }), null, "an unknown scheme payload has no identity");
});

test("F1/F2: an unidentifiable payload, a v1 header or X-PAYMENT never reaches an evaluation", async () => {
  const env = claimsEnv();
  const settle = { ok: true, tx: "0xf2", settled: 0 };
  const s = stack(USER, settle);
  const calls = { n: 0 };
  const odd = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": encode({ x402Version: 2, accepted: { network: "eip155:8453" }, payload: { foo: 1 } }) }), env, s, evaluate(s, calls));
  assert.equal(odd.status, 402);
  assert.equal(((await odd.json()) as { error: string }).error, "payment_unrecognized");
  const v1 = encode({ x402Version: 1, scheme: "exact", network: "base", payload: { signature: "0x01", authorization: { from: USER, nonce: "0x99", validBefore: inAMinute() } } });
  for (const headers of [{ "PAYMENT-SIGNATURE": v1 }, { "X-PAYMENT": v1 }]) {
    const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, headers), env, s, evaluate(s, calls));
    assert.equal(res.status, 402, JSON.stringify(headers).slice(0, 20));
  }
  assert.deepEqual([calls.n, settle.settled], [0, 0]);
});

test("F3: an authorization about to expire, or valid beyond its claim, is refused before any work", async () => {
  const env = claimsEnv();
  const settle = { ok: true, tx: "0xf3", settled: 0 };
  const s = stack(USER, settle);
  const calls = { n: 0 };
  const now = Math.floor(Date.now() / 1000);
  for (const [validBefore, error] of [[now + 7, "authorization_expires_too_soon"], [now + 2 * 86400, "authorization_valid_too_long"]] as const) {
    const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, `0x${validBefore}`, String(validBefore)) }), env, s, evaluate(s, calls));
    assert.equal(res.status, 402);
    assert.equal(((await res.json()) as { error: string }).error, error);
  }
  assert.deepEqual([calls.n, settle.settled], [0, 0]);
});

test("F3: a payer has at most 8 payments in flight, and is held back after 5 settlement refusals", async () => {
  const env = claimsEnv();
  const s = stack(USER, { ok: true, tx: "0xf4", settled: 0 });
  const busy = await Promise.all(Array.from({ length: 9 }, (_, i) => handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, `0x4${i}`) }), env, s, evaluate(s, { n: 0 }, 30))));
  const codes = busy.map((r) => r.status);
  assert.equal(codes.filter((c) => c === 429).length, 1, "the ninth waits");
  assert.equal(codes.filter((c) => c === 409).length, 0);

  const failing = stack(USER, { ok: false, tx: "0x0", settled: 0 });
  const other = "0x3333333333333333333333333333333333333333";
  for (let i = 0; i < 5; i++) {
    const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(other, `0x5${i}`) }), env, failing, evaluate(failing));
    assert.equal(res.status, 402);
  }
  const calls = { n: 0 };
  const held = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(other, "0x60") }), env, failing, evaluate(failing, calls));
  assert.equal(held.status, 429);
  assert.equal(((await held.json()) as { error: string }).error, "payer_settlement_failures");
  assert.equal(calls.n, 0, "not evaluated");
  const ok = stack(USER, { ok: true, tx: "0xf4b", settled: 0 });
  const fine = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, "0x61") }), env, ok, evaluate(ok));
  assert.equal(fine.status, 200, "another payer is unaffected");
});

test("one settlement transaction pays once: a facilitator confirming it twice releases nothing more", async () => {
  const env: WorkerEnv = { ...claimsEnv(), CREDITS: namespace((st) => new CreditLedger(st)) };
  const s = stack(USER, { ok: true, tx: "0xsame", settled: 0 });
  const first = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, "0x70") }), env, s, evaluate(s));
  const second = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, "0x71") }), env, s, evaluate(s));
  assert.deepEqual([first.status, second.status], [200, 402]);
  assert.equal(((await second.json()) as { error: string }).error, "payment_settlement_reused");
  const pack = await handleCredits(req("/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": payment(USER, "0x72") }), env, stack(USER, { ok: true, tx: "0xsame", settled: 0 }));
  assert.equal(pack.status, 402, "no pack for a reused transaction");
  assert.equal(((await pack.json()) as { token?: string }).token, undefined);
});

test("unpaid, any body gets the challenge (with the reason it would be refused); paid, an invalid body is a 422", async () => {
  const s = stack(USER, { ok: true, tx: "0xf5", settled: 0 });
  const calls = { n: 0 };
  const unpaid = await handleProtected(req("/v1/risk-check", { wallet: "not-a-wallet" }), {}, s, evaluate(s, calls));
  assert.equal(unpaid.status, 402);
  assert.ok(unpaid.headers.get("PAYMENT-REQUIRED"));
  assert.deepEqual(((await unpaid.json()) as { request_error?: { field?: string } }).request_error?.field, "wallet");
  const typo = await handleProtected(req("/v1/risk-check", { wallet: WALLET, contxt: "x" }, { "PAYMENT-SIGNATURE": payment(USER, "0x80") }), claimsEnv(), s, evaluate(s, calls));
  assert.equal(typo.status, 422);
  assert.equal(calls.n, 0);
  // A credit pack is not a listed service: without an amount it is a 422, never a challenge for a guessed pack.
  const pack = await handleCredits(new Request("https://x402check.xyz/v1/credits", { method: "POST" }), { CREDITS: namespace((st) => new CreditLedger(st)) }, s);
  assert.equal(pack.status, 422);
});

test("the Worker: every POST to a paid route is limited (credentialed traffic separately); 429 and preflight carry the headers", async () => {
  const seen: string[] = [];
  const limiter = (allow: boolean) => ({ limit: async ({ key }: { key: string }) => (seen.push(key), { success: allow }) });
  const env: WorkerEnv = { PROVIDER_HOST: "x402check.xyz", UNPAID_LIMITER: limiter(false), PAID_LIMITER: limiter(false) } as WorkerEnv;
  const post = (headers: Record<string, string>) => worker.fetch(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", body: "{}", headers: { "CF-Connecting-IP": "203.0.113.9", ...headers } }), env);
  const fake = await post({ Authorization: "Bearer whatever" });
  assert.equal(fake.status, 429, "a malformed credential is unpaid traffic");
  await post({ Authorization: `Bearer x402c_${"A".repeat(43)}` });
  await post({ "PAYMENT-SIGNATURE": payment(USER) });
  await post({ "PAYMENT-SIGNATURE": btoa(JSON.stringify({ x402Version: 1 })) });
  assert.deepEqual(seen, ["unpaid:203.0.113.9", "paid:203.0.113.9", "paid:203.0.113.9", "unpaid:203.0.113.9"]);
  assert.equal(fake.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(fake.headers.get("Access-Control-Allow-Origin"), "*");
  const preflight = await worker.fetch(new Request("https://x402check.xyz/v1/risk-check", { method: "OPTIONS" }), env);
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers.get("Strict-Transport-Security") ?? "", /max-age/);
  assert.equal(preflight.headers.get("Access-Control-Allow-Methods"), "GET, POST, OPTIONS");
});

test("only public key members are published: a next key pasted with its private part is not published at all", async () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const next = { kty: "EC", crv: "P-256", x: pub.x, y: pub.y, kid: "jev-attest-v9", alg: "ES256", use: "sig" };
  const docs = async (value: Record<string, unknown>) => {
    const env: WorkerEnv = { PROVIDER_HOST: "localhost:8799", JEV_ATTEST_NEXT_PUBLIC_JWK: JSON.stringify(value) };
    const jwks = (await (await worker.fetch(new Request("http://localhost:8799/.well-known/jwks.json"), env)).json()) as { keys: Array<Record<string, unknown>> };
    const did = (await (await worker.fetch(new Request("http://localhost:8799/.well-known/did.json"), env)).json()) as { verificationMethod: Array<{ publicKeyJwk: Record<string, unknown> }> };
    return { jwks: jwks.keys, did: did.verificationMethod.map((m) => m.publicKeyJwk) };
  };
  const ok = await docs({ ...next, extra: "dropped" });
  assert.deepEqual(ok.jwks.find((k) => k.kid === "jev-attest-v9"), next, "public members only");
  assert.deepEqual(ok.did.find((k) => k.kid === "jev-attest-v9"), next);
  const leaked = await docs({ ...next, d: "c2VjcmV0" });
  assert.equal(leaked.jwks.some((k) => k.kid === "jev-attest-v9" || "d" in k), false);
  assert.equal(leaked.did.some((k) => k.kid === "jev-attest-v9" || "d" in k), false);
});

// The 2026-10-03 security review: a decoy scheme object next to the real one (H1), a payer with
// a wrong EIP-55 checksum (M1), facilitator-side refusals (L3), a Solana delegate paying from
// someone else's account (L4).
import { paymentScheme, settlementIdentity } from "../deploy/payment-claims.js";
import { payerRefusal } from "../deploy/http-util.js";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { createTransferCheckedInstruction, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from "@solana/spl-token";

const soon = () => String(Math.floor(Date.now() / 1000) + 300);
const permit2Route = { scheme: "exact", network: "eip155:143", extra: { assetTransferMethod: "permit2" } };
const eip3009Route = { scheme: "exact", network: "eip155:8453" };
const solanaRoute = { scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" };

test("H1: exactly one scheme payload, the one the route takes: a decoy next to it is refused before any work", async () => {
  const permit = { from: USER, nonce: "77", deadline: soon(), permitted: { token: "0x0", amount: "1000" }, spender: "0x0", witness: {} };
  const decoy = { from: "0x2222222222222222222222222222222222222222", nonce: "0x99", validBefore: soon() };
  assert.equal(paymentScheme({ accepted: permit2Route, payload: { signature: "0x01", permit2Authorization: permit } })?.kind, "permit2");
  assert.equal(paymentScheme({ accepted: permit2Route, payload: { signature: "0x01", permit2Authorization: permit, authorization: decoy } }), null, "decoy next to Permit2");
  assert.equal(paymentScheme({ accepted: permit2Route, payload: { signature: "0x01", authorization: decoy } }), null, "EIP-3009 on a Permit2 route");
  assert.equal(paymentScheme({ accepted: eip3009Route, payload: { signature: "0x01", permit2Authorization: permit } }), null, "Permit2 on an EIP-3009 route");
  assert.equal(paymentScheme({ accepted: solanaRoute, payload: { transaction: "AQ==", authorization: decoy } }), null, "decoy next to a Solana transaction");
  assert.equal(paymentScheme({ accepted: solanaRoute, payload: { authorization: decoy } }), null, "EVM payload on a Solana route");

  const env = claimsEnv();
  const s = stack(USER, { ok: true, tx: "0xh1", settled: 0 });
  const calls = { n: 0 };
  const header = encode({ x402Version: 2, accepted: permit2Route, payload: { signature: "0x01", permit2Authorization: permit, authorization: decoy } });
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header }), env, s, evaluate(s, calls));
  assert.equal(res.status, 402);
  assert.equal(((await res.json()) as { error: string }).error, "payment_unrecognized");
  assert.equal(calls.n, 0, "never evaluated");
});

test("M1: an SDN-listed payer with a wrong EIP-55 checksum is still screened as listed", async () => {
  const listed = OFAC_SDN_ADDRESSES.find(([a]) => /^0x[0-9a-f]{40}$/.test(a) && /[a-f]/.test(a))?.[0] as string;
  const i = [...listed].findIndex((c, k) => k > 1 && /[a-f]/.test(c));
  const flipped = listed.slice(0, i) + (listed[i] as string).toUpperCase() + listed.slice(i + 1);
  const s = stack(flipped, { ok: true, tx: "0xm1", settled: 0 });
  const calls = { n: 0 };
  const res = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(flipped, "0x0m1") }), claimsEnv(), s, evaluate(s, calls));
  assert.equal(res.status, 403);
  assert.equal(calls.n, 0);
});

test("L3: only refusals the payer is answerable for count against the payer", () => {
  for (const r of ["insufficient_funds", "invalid_exact_evm_insufficient_balance", "invalid_exact_evm_signature", "invalid_exact_evm_nonce_already_used", "invalid_exact_evm_payload_authorization_valid_before", "invalid_exact_evm_recipient_mismatch"]) assert.equal(payerRefusal(r), true, r);
  for (const r of ["settlement_pending", "invalid_exact_evm_transaction_failed", "post_settlement_transfer_not_confirmed", "invalid_transaction_state", "unexpected_settle_error", "something_new", undefined]) assert.equal(payerRefusal(r), false, String(r));
});

test("L4: a Solana payment is admitted only from the payer's own token account; a delegate's is refused", async () => {
  const mint = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  const feePayer = Keypair.generate();
  const payer = Keypair.generate();
  const owner = Keypair.generate(); // someone else, whose account the delegate would spend
  const merchant = getAssociatedTokenAddressSync(mint, Keypair.generate().publicKey);
  const wire = (source: PublicKey) => {
    const tx = new Transaction({ feePayer: feePayer.publicKey, recentBlockhash: "11111111111111111111111111111111" });
    tx.add(createTransferCheckedInstruction(source, mint, merchant, payer.publicKey, 3500n, 6, [], TOKEN_PROGRAM_ID));
    tx.partialSign(payer);
    return tx.serialize({ requireAllSignatures: false }).toString("base64");
  };
  const header = (tx: string) => encode({ x402Version: 2, accepted: solanaRoute, payload: { transaction: tx } });
  const svmStack = (): Stack => {
    const st = stack(USER, { ok: true, tx: `sig${Math.random()}`, settled: 0 });
    // The Solana payload as-is: the mock stack's EVM default must not be filled in.
    (st as unknown as { http: { processHTTPRequest: (c: HTTPRequestContext) => Promise<unknown> } }).http.processHTTPRequest = async (ctx: HTTPRequestContext) => {
      const h = ctx.adapter.getHeader("PAYMENT-SIGNATURE");
      return h ? { type: "payment-verified", paymentPayload: JSON.parse(atob(h)) as unknown, paymentRequirements: { network: solanaRoute.network } } : { type: "payment-error", response: { status: 402, headers: {}, body: {} } };
    };
    return st;
  };
  const own = svmStack();
  const ok = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header(wire(getAssociatedTokenAddressSync(mint, payer.publicKey))) }), claimsEnv(), own, evaluate(own));
  assert.equal(ok.status, 200, "own associated token account");
  const delegated = svmStack();
  const calls = { n: 0 };
  const refused = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header(wire(getAssociatedTokenAddressSync(mint, owner.publicKey))) }), claimsEnv(), delegated, evaluate(delegated, calls));
  assert.equal(refused.status, 402);
  assert.match(((await refused.json()) as { detail: string }).detail, /own associated token account/);
  assert.equal(calls.n, 0);
});

test("a settlement's identity keeps a Solana signature's case and lowercases an EVM hash", async () => {
  assert.notEqual(await settlementIdentity("solana:x", "AbC"), await settlementIdentity("solana:x", "abc"));
  assert.equal(await settlementIdentity("eip155:8453", "0xABC"), await settlementIdentity("eip155:8453", "0xabc"));
});

test("a challenge never waits on a slow Solana RPC, and never echoes the query string", async () => {
  const { BoundedSvmScheme } = await import("../deploy/protected.js");
  const { fetchAdapter } = await import("../deploy/http-util.js");
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
    String(input instanceof Request ? input.url : input).includes("slow-solana.example") ? new Promise<Response>(() => undefined) : realFetch(input, init)) as typeof fetch;
  try {
    const scheme = new BoundedSvmScheme({ rpcUrl: "https://slow-solana.example" });
    const started = Date.now();
    const out = await scheme.enhancePaymentRequirements(
      { scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "2000", asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", payTo: "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X", maxTimeoutSeconds: 300, extra: {} } as never,
      { x402Version: 2, scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", extra: { feePayer: "DeXterR2kQmVeQ5RZt9HjdWZNcJRRBjZD5YWFYxB64JU" } } as never,
      [],
    );
    assert.ok(Date.now() - started < 2000, "bounded");
    assert.equal((out.extra as { feePayer?: string }).feePayer, "DeXterR2kQmVeQ5RZt9HjdWZNcJRRBjZD5YWFYxB64JU");
    assert.equal((out.extra as { recentBlockhash?: string }).recentBlockhash, undefined);
  } finally {
    globalThis.fetch = realFetch;
  }
  const adapter = fetchAdapter(new Request("https://x402check.xyz/v1/risk-check?utm=1&x=%3Cscript%3E", { method: "POST" }), {});
  assert.equal(adapter.getUrl(), "https://x402check.xyz/v1/risk-check");
});

test("an unpaid challenge reuses a recent Solana blockhash for 15 s instead of asking the RPC every time", async () => {
  const { BoundedSvmScheme } = await import("../deploy/protected.js");
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (!url.includes("counting-solana.example")) return realFetch(input, init);
    calls++;
    const { id } = JSON.parse(String(init?.body)) as { id: unknown };
    return Response.json({ jsonrpc: "2.0", id, result: { context: { slot: 1 }, value: { blockhash: `Hash${calls}111111111111111111111111111111111111`, lastValidBlockHeight: 1000 + calls } } });
  }) as typeof fetch;
  try {
    const scheme = new BoundedSvmScheme({ rpcUrl: "https://counting-solana.example" });
    const ask = () =>
      scheme.enhancePaymentRequirements(
        { scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "2000", asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", payTo: "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X", maxTimeoutSeconds: 300, extra: {} } as never,
        { x402Version: 2, scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", extra: { feePayer: "DeXterR2kQmVeQ5RZt9HjdWZNcJRRBjZD5YWFYxB64JU" } } as never,
        [],
      );
    const first = await ask();
    const second = await ask();
    assert.equal(calls, 1, "one RPC call for two challenges");
    assert.equal((first.extra as { recentBlockhash?: string }).recentBlockhash, (second.extra as { recentBlockhash?: string }).recentBlockhash);
    assert.equal((second.extra as { feePayer?: string }).feePayer, "DeXterR2kQmVeQ5RZt9HjdWZNcJRRBjZD5YWFYxB64JU");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a client gone during its evaluation is charged and recorded undelivered; the same payment resent for the same request receives that verdict, never evaluated or charged again", async () => {
  const kv = memoryKv();
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s)), RATE: kv };
  const settle = { ok: true, tx: "0xeee", settled: 0 };
  const s = stack(USER, settle);
  const header = payment(USER, "0x14");
  const controller = new AbortController();
  const gone = new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": header }, body: JSON.stringify({ wallet: WALLET }), signal: controller.signal });
  const handed: Promise<unknown>[] = [];
  let evaluations = 0;
  const evaluate = (stackUsed: Stack) => async (r: Request) => {
    evaluations++;
    return createHandler(stackUsed.deps)(r);
  };
  // The client disconnects while its check is being evaluated: the verdict is produced, so it is settled.
  const res = await handleProtected(gone, env, s, async (r) => {
    controller.abort();
    return evaluate(s)(r);
  }, { waitUntil: (p) => void handed.push(p) });
  assert.equal(res.status, 200);
  const verdict = await res.text();
  assert.equal(settle.settled, 1, "settled once");
  assert.equal(handed.length, 1, "the work runs to completion even if the isolate would cancel the request");
  assert.equal((JSON.parse(kv.data.get("st:eip155:8453:0xeee") ?? "{}") as { undelivered?: boolean }).undelivered, true);
  // Resent for the same request: the verdict it paid for, as it was produced, with its receipt.
  const again = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header }), env, s, evaluate(s));
  assert.deepEqual([again.status, again.headers.get("X-Payment-Delivery")], [200, "resent"]);
  assert.equal(await again.text(), verdict, "the same verdict");
  assert.ok(again.headers.get("PAYMENT-RESPONSE"), "with its settlement receipt");
  assert.deepEqual([evaluations, settle.settled], [1, 1], "no second evaluation, no second charge");
  const record = JSON.parse(kv.data.get("st:eip155:8453:0xeee") ?? "{}") as { undelivered?: boolean; delivered?: string };
  assert.deepEqual([record.undelivered, record.delivered], [undefined, "resent"], "the record says it was delivered");
  // The same payment for another request is used: nothing is evaluated for it.
  const other = await handleProtected(req("/v1/risk-check", { wallet: USER }, { "PAYMENT-SIGNATURE": header }), env, s, evaluate(s));
  assert.equal(other.status, 409, "the settled payment is used");
  // In production the facilitator refuses the used authorization before admission: the same request
  // still receives its verdict, and another request still gets the refusal.
  const refusing = { ...s, http: { ...s.http, processHTTPRequest: async () => ({ type: "payment-error", response: { status: 402, headers: {}, body: { error: "invalid_exact_evm_payload_authorization_nonce" } } }) } } as unknown as Stack;
  const viaRefusal = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header }), env, refusing, evaluate(refusing));
  assert.deepEqual([viaRefusal.status, await viaRefusal.text()], [200, verdict]);
  const refused = await handleProtected(req("/v1/risk-check", { wallet: USER }, { "PAYMENT-SIGNATURE": header }), env, refusing, evaluate(refusing));
  assert.equal(refused.status, 402);
  const batch = await handleProtected(req("/v1/risk-check/batch", { requests: [{ wallet: WALLET }] }, { "PAYMENT-SIGNATURE": header }), env, refusing, evaluate(refusing));
  assert.equal(batch.status, 402, "another route is another request");
  assert.deepEqual([evaluations, settle.settled], [1, 1]);
  // A verdict that reached its client is not kept: a resend of a delivered payment is refused.
  const delivered = payment(USER, "0x15");
  const s2 = stack(USER, { ok: true, tx: "0xef0", settled: 0 });
  assert.equal((await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": delivered }), env, s2, evaluate(s2))).status, 200);
  assert.equal((await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": delivered }), env, s2, evaluate(s2))).status, 409);
});

test("a verdict is kept only for a settled payment, served only for the same request, and never past its size bound", async () => {
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)) };
  const kept = { request: "r1", status: 200, headers: { "content-type": "application/json" }, body: "{}" };
  const claim = await claimPayment(env, "kept-1");
  assert.ok(claim.claimed);
  await claim.keep(kept);
  assert.equal(await keptVerdict(env, "kept-1", "r1"), null, "a pending claim keeps nothing");
  await claim.settled();
  await claim.keep(kept);
  assert.deepEqual(await keptVerdict(env, "kept-1", "r1"), kept);
  assert.equal(await keptVerdict(env, "kept-1", "r2"), null, "another request");
  assert.equal(await keptVerdict(env, "kept-2", "r1"), null, "another payment");
  const big = await claimPayment(env, "kept-3");
  assert.ok(big.claimed);
  await big.settled();
  await big.keep({ ...kept, body: "x".repeat(KEPT_MAX_BYTES + 1) });
  assert.equal(await keptVerdict(env, "kept-3", "r1"), null, "too large to keep");
  // A released claim (nothing settled) keeps nothing either.
  const released = await claimPayment(env, "kept-4");
  assert.ok(released.claimed);
  await released.release();
  await released.keep(kept);
  assert.equal(await keptVerdict(env, "kept-4", "r1"), null);
});

test("a resend while the abandoned check still runs is told to wait, not to pay again; once settled it receives the verdict (2026-10-18 review, R1, R2, R4)", async () => {
  const kv = memoryKv();
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)), RATE: kv };
  const settle = { ok: true, tx: "0xc01", settled: 0 };
  const s = stack(USER, settle);
  const header = payment(USER, "0x60");
  const controller = new AbortController();
  let during: Response | undefined;
  const first = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": header }, body: JSON.stringify({ wallet: WALLET }), signal: controller.signal }), env, s, async (r) => {
    controller.abort();
    // The client, having given up, sends the same payment again while the check is still evaluated.
    during = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header }), env, s, (inner) => createHandler(s.deps)(inner));
    return createHandler(s.deps)(r);
  });
  assert.equal(first.status, 200);
  const verdict = await first.text();
  assert.ok(during);
  assert.deepEqual([during.status, ((await during.json()) as { error?: string }).error, during.headers.get("Retry-After")], [409, "payment_in_progress", "5"]);
  // R2: the resend comes back with its authorization about to expire (the same authorization, later):
  // still the verdict it paid for, not a refusal.
  const late = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(USER, "0x60", String(Math.floor(Date.now() / 1000) + 20)) }), env, s, (inner) => createHandler(s.deps)(inner));
  assert.deepEqual([late.status, late.headers.get("X-Payment-Delivery"), await late.text()], [200, "resent", verdict]);
  assert.equal(settle.settled, 1);
  // R4: a client that leaves while the settlement is recorded has not received its verdict either: it is kept.
  const leaving = new AbortController();
  const recording: KVNamespace & { data: Map<string, string> } = {
    ...kv,
    data: kv.data,
    put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
      if (key.startsWith("st:")) leaving.abort();
      return kv.put(key, value, opts);
    },
  } as KVNamespace & { data: Map<string, string> };
  const s2 = stack(USER, { ok: true, tx: "0xc02", settled: 0 });
  const header2 = payment(USER, "0x61");
  const paid = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": header2 }, body: JSON.stringify({ wallet: WALLET }), signal: leaving.signal }), { ...env, RATE: recording }, s2, (r) => createHandler(s2.deps)(r));
  assert.equal(paid.status, 200);
  assert.equal((JSON.parse(kv.data.get("st:eip155:8453:0xc02") ?? "{}") as { undelivered?: boolean }).undelivered, true);
  const again = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": header2 }), env, s2, (r) => createHandler(s2.deps)(r));
  assert.deepEqual([again.status, again.headers.get("X-Payment-Delivery")], [200, "resent"]);
});

test("a verdict resent past the facilitator's refusal goes only to a payer that still passes the screen, and its record says unverified (2026-10-18 review, R3)", async () => {
  const kv = memoryKv();
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)), RATE: kv };
  const s = stack(USER, { ok: true, tx: "0xc03", settled: 0 });
  const refusing = { ...s, http: { ...s.http, processHTTPRequest: async () => ({ type: "payment-error", response: { status: 402, headers: {}, body: { error: "invalid_payment" } } }) } } as unknown as Stack;
  const body = JSON.stringify({ wallet: WALLET });
  const keepFor = async (header: string, record?: string) => {
    const id = await paymentIdentity(JSON.parse(atob(header)) as unknown);
    const claim = await claimPayment(env, id);
    assert.ok(claim.claimed);
    await claim.settled();
    await claim.keep({ request: await requestFingerprint("/v1/risk-check", body), status: 200, headers: { "content-type": "application/json" }, body: "{\"checked\":true}", ...(record ? { record } : {}) });
  };
  // A payer listed on the SDN list since it paid: nothing is served past the refusal.
  const listed = OFAC_SDN_ADDRESSES.find(([a]) => /^0x[0-9a-fA-F]{40}$/.test(a))?.[0] as string;
  const fromListed = payment(listed, "0x62");
  await keepFor(fromListed);
  assert.equal((await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": fromListed }), env, refusing, (r) => createHandler(refusing.deps)(r))).status, 402);
  // Another payer receives it, and the record says the payment could not be verified again.
  await kv.put("st:eip155:8453:0xc03", JSON.stringify({ at: "2026-10-18T00:00:00Z", path: "/v1/risk-check", undelivered: true }));
  const fromUser = payment(USER, "0x63");
  await keepFor(fromUser, "st:eip155:8453:0xc03");
  const served = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": fromUser }), env, refusing, (r) => createHandler(refusing.deps)(r));
  assert.deepEqual([served.status, served.headers.get("X-Payment-Delivery")], [200, "resent"]);
  const record = JSON.parse(kv.data.get("st:eip155:8453:0xc03") ?? "{}") as { undelivered?: boolean; delivered?: string };
  assert.deepEqual([record.undelivered, record.delivered], [undefined, "resent_unverified"]);
});

test("the work handed to waitUntil starts before any state changes: a claim, a debit or a pack is never left half done by a cancelled request", async () => {
  // A cancelled request runs only what was handed to waitUntil. Admission refusing (a listed payer)
  // shows the hand-off already covers it: before 0.6.15 admission ran first, and a client gone
  // during it left its payment claimed for a day (the production probe of 2026-10-16).
  const listed = OFAC_SDN_ADDRESSES.find(([a]) => /^0x[0-9a-fA-F]{40}$/.test(a))?.[0] as string;
  const handed: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => void handed.push(p) };
  const s = stack(listed, { ok: true, tx: "0xa1", settled: 0 });
  const refused = await handleProtected(req("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": payment(listed, "0x40") }), {}, s, (r) => createHandler(s.deps)(r), ctx);
  assert.deepEqual([refused.status, handed.length], [403, 1]);

  // Credits: the debit is inside the work too (an empty balance is refused from within it).
  const env: WorkerEnv = { CREDITS: namespace((st) => new CreditLedger(st)) };
  const bought = await handleCredits(req("/v1/credits", { amount_usd: 0.1 }, { "PAYMENT-SIGNATURE": payment(USER, "0x41") }), env, stack(USER, { ok: true, tx: "0xa2", settled: 0 }));
  const { token } = (await bought.json()) as { token: string };
  handed.length = 0;
  const spender = stack(USER, { ok: true, tx: "0x0", settled: 0 });
  const controller = new AbortController();
  const gone = new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ wallet: WALLET }), signal: controller.signal });
  // A caller gone during its evaluation is charged: the verdict was produced (refunding it would
  // make an abandoned check a free evaluation, again and again).
  const left = await handleProtected(gone, env, spender, async (r) => {
    controller.abort();
    return createHandler(spender.deps)(r);
  }, ctx);
  assert.deepEqual([left.status, handed.length], [200, 1]);
  const balanceOf = async () => ((await (await handleCredits(new Request("https://x402check.xyz/v1/credits", { headers: { Authorization: `Bearer ${token}` } }), env, spender)).json()) as { balance_usd: string }).balance_usd;
  assert.equal(await balanceOf(), "$0.099", "charged for the verdict it left behind");
  // A caller already gone when its check would start: nothing is evaluated, and the debit goes back.
  const early = new AbortController();
  early.abort();
  let evaluated = 0;
  const before = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ wallet: WALLET }), signal: early.signal }), env, spender, async (r) => {
    evaluated++;
    return createHandler(spender.deps)(r);
  }, ctx);
  assert.deepEqual([before.status, evaluated, await balanceOf()], [499, 0, "$0.099"]);

  // A buyer gone before settlement: nothing settles, and the same payment can buy the pack later.
  const settle = { ok: true, tx: "0xa3", settled: 0 };
  const claims: WorkerEnv = { CREDITS: namespace((st) => new CreditLedger(st)), PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)) };
  const header = payment(USER, "0x42");
  const buyer = new AbortController();
  buyer.abort();
  const abandoned = await handleCredits(new Request("https://x402check.xyz/v1/credits", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": header }, body: JSON.stringify({ amount_usd: 1 }), signal: buyer.signal }), claims, stack(USER, settle), ctx);
  assert.deepEqual([abandoned.status, settle.settled], [499, 0]);
  const later = await handleCredits(req("/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": header }), claims, stack(USER, settle));
  assert.deepEqual([later.status, settle.settled], [200, 1]);

  // A buyer who leaves during the settlement: the money has moved, so the record says the new token reached nobody.
  const kv = memoryKv();
  const leaving = new AbortController();
  const base = stack(USER, { ok: true, tx: "0xa4", settled: 0 });
  const settling = { ...base, http: { ...base.http, processSettlement: async (...a: Parameters<Stack["http"]["processSettlement"]>) => {
    leaving.abort();
    return base.http.processSettlement(...a);
  } } } as Stack;
  await handleCredits(new Request("https://x402check.xyz/v1/credits", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": payment(USER, "0x43") }, body: JSON.stringify({ amount_usd: 1 }), signal: leaving.signal }), { ...claims, RATE: kv }, settling, ctx);
  assert.equal((JSON.parse(kv.data.get("st:eip155:8453:0xa4") ?? "{}") as { undelivered?: boolean }).undelivered, true);
});

test("a buyer can hold the token before paying: a pack bought as a top-up of a self-made token credits it", async () => {
  const env: WorkerEnv = { CREDITS: namespace((st) => new CreditLedger(st)) };
  const own = `x402c_${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")}`;
  const bought = await handleCredits(req("/v1/credits", { amount_usd: 0.1 }, { "PAYMENT-SIGNATURE": payment(USER, "0x44"), Authorization: `Bearer ${own}` }), env, stack(USER, { ok: true, tx: "0xa5", settled: 0 }));
  assert.equal(bought.status, 200);
  assert.equal(((await bought.json()) as { token?: string }).token, undefined, "the token is never echoed: the buyer already holds it");
  const balance = await handleCredits(new Request("https://x402check.xyz/v1/credits", { headers: { Authorization: `Bearer ${own}` } }), env, stack(USER, { ok: true, tx: "0x0", settled: 0 }));
  assert.equal(((await balance.json()) as { balance_usd: string }).balance_usd, "$0.10");
});

test("an evaluation abandoned by its client is paid: one authorization abandoned in a loop buys one settled check, never free ones", async () => {
  // 2026-10-16/17 reviews: releasing the payment after an abandoned evaluation (counted or not) let one
  // signed authorization buy evaluation after evaluation. A produced verdict is now settled.
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s)) };
  const settle = { ok: true, tx: "0xb1", settled: 0 };
  const s = stack(USER, settle);
  const header = payment(USER, "0x50");
  let evaluations = 0;
  const abandon = async () => {
    const controller = new AbortController();
    const r = new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": header }, body: JSON.stringify({ wallet: WALLET }), signal: controller.signal });
    return handleProtected(r, env, s, async (inner) => {
      evaluations++;
      controller.abort();
      return createHandler(s.deps)(inner);
    });
  };
  const answers: Array<[number, string | null]> = [];
  for (let i = 0; i < 4; i++) {
    const r = await abandon();
    answers.push([r.status, r.headers.get("X-Payment-Delivery")]);
  }
  // The first is evaluated and settled; each resend of the same request receives that same verdict.
  assert.deepEqual(answers, [[200, null], [200, "resent"], [200, "resent"], [200, "resent"]]);
  assert.deepEqual([evaluations, settle.settled], [1, 1], "one evaluation, paid");
  // A client already gone before its check starts costs nothing and counts nothing.
  const env2: WorkerEnv = { PAYMENT_CLAIMS: namespace((st) => new PaymentClaim(st)) };
  const gone = new AbortController();
  gone.abort();
  let ran = 0;
  for (let i = 0; i < 7; i++) {
    const res = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": payment(USER, "0x51") }, body: JSON.stringify({ wallet: WALLET }), signal: gone.signal }), env2, s, async (inner) => {
      ran++;
      return createHandler(s.deps)(inner);
    });
    assert.equal(res.status, 499);
  }
  assert.equal(ran, 0);
  // A client that leaves while its payment settles: charged, and the record says the verdict reached nobody.
  const kv = memoryKv();
  const leaving = new AbortController();
  const base = stack(USER, { ok: true, tx: "0xb2", settled: 0 });
  const settling = { ...base, http: { ...base.http, processSettlement: async (...a: Parameters<Stack["http"]["processSettlement"]>) => {
    leaving.abort();
    return base.http.processSettlement(...a);
  } } } as Stack;
  const paid = await handleProtected(new Request("https://x402check.xyz/v1/risk-check", { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": payment(USER, "0x52") }, body: JSON.stringify({ wallet: WALLET }), signal: leaving.signal }), { ...env2, RATE: kv }, settling, (r) => createHandler(settling.deps)(r));
  assert.equal(paid.status, 200);
  assert.equal((JSON.parse(kv.data.get("st:eip155:8453:0xb2") ?? "{}") as { undelivered?: boolean }).undelivered, true);
});

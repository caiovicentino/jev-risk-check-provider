import { createHmac } from "node:crypto";
import assert from "node:assert/strict";
import { beforeEach, describe, test } from "node:test";
import { clearDidCache, didWebDocumentUrl, parseSubject, requestHash, verifyAttestation } from "../src/index.js";
import {
  b64url,
  claims,
  DEFAULT_HEADER,
  DID_URL,
  didDocument,
  didFetch,
  EVM,
  flipBase58Case,
  ISSUER,
  json,
  KID,
  makeIssuerKey,
  mockFetch,
  nowSeconds,
  providerStyleSigner,
  signJws,
  SOL,
  type IssuerKey,
} from "./helpers.js";

let key: IssuerKey;

beforeEach(async () => {
  clearDidCache();
  key = await makeIssuerKey();
});

describe("verifyAttestation: signature and key resolution", () => {
  test("a valid attestation verifies and the key comes from the issuer's did.json only", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const { fetch, calls } = didFetch(didDocument(key.publicJwk));
    const v = await verifyAttestation(jws, { fetch });
    assert.deepEqual(v.failures, []);
    assert.equal(v.valid, true);
    assert.equal(v.claims?.sub, EVM);
    assert.equal(v.claims?.tier, "high");
    assert.equal(v.issuer, ISSUER);
    assert.equal(v.verificationMethod, `${ISSUER}#${KID}`);
    assert.deepEqual(calls.map((c) => c.url), [DID_URL]);
    assert.equal(calls[0]?.init.method, "GET");
  });

  test("interop: a signature produced like the provider's (node:crypto, ieee-p1363) verifies", async () => {
    const signer = providerStyleSigner();
    const { fetch } = didFetch(didDocument(signer.publicJwk));
    const v = await verifyAttestation(signer.sign(claims()), { fetch });
    assert.equal(v.valid, true, v.failures.join());
  });

  test("tampered payload fails (score raised after signing)", async () => {
    const jws = await signJws(claims({ score: 20, tier: "critical" }), key.privateKey);
    const [h, , s] = jws.split(".");
    const forged = `${h}.${b64url(JSON.stringify(claims({ score: 95, tier: "low" })))}.${s}`;
    const v = await verifyAttestation(forged, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.equal(v.valid, false);
    assert.deepEqual(v.failures, ["signature_invalid"]);
    assert.equal(v.claims?.tier, "low", "decoded claims are still returned, but untrusted");
  });

  test("tampered signature fails", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const [h, p, s] = jws.split(".") as [string, string, string];
    const sig = Buffer.from(s, "base64url");
    sig[10] = (sig[10] as number) ^ 0xff;
    const v = await verifyAttestation(`${h}.${p}.${b64url(sig)}`, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["signature_invalid"]);
  });

  test("a DER-encoded signature is rejected (ES256 requires the 64-byte r||s form)", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const [h, p, s] = jws.split(".") as [string, string, string];
    const raw = Buffer.from(s, "base64url");
    const int = (b: Buffer): Buffer => {
      let v = b;
      while (v.length > 1 && v[0] === 0) v = v.subarray(1);
      return (v[0] as number) & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v;
    };
    const r = int(raw.subarray(0, 32));
    const sPart = int(raw.subarray(32));
    const der = Buffer.concat([Buffer.from([0x30, r.length + sPart.length + 4, 0x02, r.length]), r, Buffer.from([0x02, sPart.length]), sPart]);
    const v = await verifyAttestation(`${h}.${p}.${b64url(der)}`, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["signature_invalid"]);
  });

  test("a token signed by another key under the same kid fails", async () => {
    const attacker = await makeIssuerKey();
    const jws = await signJws(claims(), attacker.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["signature_invalid"]);
  });

  test("unknown kid fails", async () => {
    const jws = await signJws(claims(), key.privateKey, { ...DEFAULT_HEADER, kid: "jev-attest-v2" });
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["unknown_kid"]);
  });

  test("a key that is not referenced by assertionMethod cannot sign attestations", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk, { inAssertion: false })).fetch });
    assert.deepEqual(v.failures, ["kid_not_in_assertion_method"]);
  });

  test("kid as an absolute DID URL or a fragment resolves to the same method", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    for (const kid of [`${ISSUER}#${KID}`, `#${KID}`]) {
      const v = await verifyAttestation(await signJws(claims(), key.privateKey, { ...DEFAULT_HEADER, kid }), { fetch });
      assert.equal(v.valid, true, `${kid}: ${v.failures.join()}`);
    }
  });

  test("a kid pointing at another DID is not resolved from that DID", async () => {
    const jws = await signJws(claims(), key.privateKey, { ...DEFAULT_HEADER, kid: `did:web:evil.example#${KID}` });
    const { fetch, calls } = didFetch(didDocument(key.publicJwk));
    const v = await verifyAttestation(jws, { fetch });
    assert.deepEqual(v.failures, ["unknown_kid"]);
    assert.deepEqual(calls.map((c) => c.url), [DID_URL]);
  });

  test("embedded jwk / jku headers and jwks_url are never used: an attacker key is rejected", async () => {
    const attacker = await makeIssuerKey();
    const header = { ...DEFAULT_HEADER, jwk: attacker.publicJwk, jku: "https://evil.example/jwks.json", x5u: "https://evil.example/cert" };
    const jws = await signJws(claims(), attacker.privateKey, header);
    const { fetch, calls } = didFetch(didDocument(key.publicJwk));
    const v = await verifyAttestation(jws, { fetch });
    assert.deepEqual(v.failures, ["signature_invalid"]);
    assert.deepEqual(calls.map((c) => c.url), [DID_URL]);
  });

  test("a DID document key with the wrong algorithm is not usable", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument({ ...key.publicJwk, alg: "ES384" as "ES256" })).fetch });
    assert.deepEqual(v.failures, ["unsupported_key"]);
  });
});

describe("verifyAttestation: algorithm and header", () => {
  test("alg none is rejected without resolving any key", async () => {
    const header = b64url(JSON.stringify({ alg: "none", typ: "risk-check+jwt", kid: KID }));
    const payload = b64url(JSON.stringify(claims()));
    const { fetch, calls } = didFetch(didDocument(key.publicJwk));
    const unsigned = await verifyAttestation(`${header}.${payload}.`, { fetch });
    assert.deepEqual(unsigned.failures, ["malformed_jws"]);
    const junk = await verifyAttestation(`${header}.${payload}.${b64url("x")}`, { fetch });
    assert.equal(junk.valid, false);
    assert.ok(junk.failures.includes("alg_not_es256"));
    assert.equal(calls.length, 0);
  });

  test("HS256 key confusion (HMAC keyed with the public key) is rejected", async () => {
    const header = b64url(JSON.stringify({ alg: "HS256", typ: "risk-check+jwt", kid: KID }));
    const payload = b64url(JSON.stringify(claims({ score: 99, tier: "low" })));
    const mac = createHmac("sha256", JSON.stringify(key.publicJwk)).update(`${header}.${payload}`).digest();
    const v = await verifyAttestation(`${header}.${payload}.${b64url(mac)}`, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.equal(v.valid, false);
    assert.deepEqual(v.failures, ["alg_not_es256"]);
  });

  test("typ other than risk-check+jwt is rejected", async () => {
    const jws = await signJws(claims(), key.privateKey, { alg: "ES256", typ: "JWT", kid: KID });
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["unexpected_typ"]);
  });

  test("crit and b64 header extensions are rejected", async () => {
    const jws = await signJws(claims(), key.privateKey, { ...DEFAULT_HEADER, crit: ["exp"] });
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["unsupported_header"]);
  });

  test("missing kid is rejected", async () => {
    const jws = await signJws(claims(), key.privateKey, { alg: "ES256", typ: "risk-check+jwt" });
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["missing_kid"]);
  });

  test("null options and odd option values never throw", async (t) => {
    const jws = await signJws(claims(), key.privateKey);
    const { fetch } = didFetch(didDocument(key.publicJwk));
    // null options → the default issuer and globalThis.fetch (stubbed: tests stay offline)
    const offline = t.mock.method(globalThis, "fetch", async () => {
      throw new TypeError("offline");
    });
    const v = await verifyAttestation(jws, null);
    assert.deepEqual(v.failures, ["did_resolution_failed"]);
    assert.equal(offline.mock.calls[0]?.arguments[0], "https://x402check.xyz/.well-known/did.json");
    assert.equal((await verifyAttestation(jws, { fetch, timeoutMs: Number.NaN })).valid, true, "an invalid timeout falls back to the default");
    assert.equal((await verifyAttestation(jws, { fetch, timeoutMs: 2 ** 40 })).valid, true);
  });

  test("a non-canonical base64url signature (padding bits set) is rejected: one signature, one encoding", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const [h, p, s] = jws.split(".") as [string, string, string];
    assert.equal(s.length % 4, 2, "a 64-byte signature leaves 4 padding bits");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(s.at(-1) as string);
    const variant = `${s.slice(0, -1)}${alphabet[last | 1]}`;
    assert.notEqual(variant, s);
    assert.deepEqual(Buffer.from(variant, "base64url"), Buffer.from(s, "base64url"), "same bytes, different string");
    const { fetch } = didFetch(didDocument(key.publicJwk));
    assert.equal((await verifyAttestation(jws, { fetch })).valid, true);
    assert.deepEqual((await verifyAttestation(`${h}.${p}.${variant}`, { fetch })).failures, ["malformed_jws"]);
  });

  test("key rotation: an unknown kid refreshes a cached DID document, at most every 30 s", async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: Date.parse("2026-09-29T12:00:00Z") });
    const v2 = await makeIssuerKey("jev-attest-v2");
    let doc = didDocument(key.publicJwk);
    const { fetch, calls } = mockFetch(() => json(200, doc));
    const at = (iso: string): Record<string, unknown> => {
      const iat = Math.floor(Date.parse(iso) / 1000);
      return claims({ iat, exp: iat + 3600 });
    };
    assert.equal((await verifyAttestation(await signJws(at("2026-09-29T12:00:00Z"), key.privateKey), { fetch })).valid, true);
    doc = { ...doc, verificationMethod: [...(doc.verificationMethod as unknown[]), { id: `${ISSUER}#jev-attest-v2`, type: "JsonWebKey2020", controller: ISSUER, publicKeyJwk: v2.publicJwk }], assertionMethod: [`${ISSUER}#${KID}`, `${ISSUER}#jev-attest-v2`] };
    const rotated = await signJws(at("2026-09-29T12:00:00Z"), v2.privateKey, { ...DEFAULT_HEADER, kid: "jev-attest-v2" });
    t.mock.timers.setTime(Date.parse("2026-09-29T12:00:10Z"));
    assert.deepEqual((await verifyAttestation(rotated, { fetch })).failures, ["unknown_kid"], "within the cooldown: no refetch");
    assert.equal(calls.length, 1);
    t.mock.timers.setTime(Date.parse("2026-09-29T12:00:31Z"));
    assert.equal((await verifyAttestation(rotated, { fetch })).valid, true, "after the cooldown: refetched, new key found");
    assert.equal(calls.length, 2);
    await verifyAttestation(rotated, { fetch });
    assert.equal(calls.length, 2, "the refreshed document is cached again");
  });

  test("malformed input never throws", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    for (const bad of ["a.b", "a.b.c.d", "!!.??.**", `${b64url("not json")}.${b64url("{}")}.${b64url("s")}`, `${b64url("[1]")}.${b64url("{}")}.${b64url("s")}`, 42 as unknown as string]) {
      const v = await verifyAttestation(bad, { fetch });
      assert.equal(v.valid, false);
      assert.deepEqual(v.failures, ["malformed_jws"], String(bad));
    }
    for (const missing of [undefined, null, "", "  "]) {
      assert.deepEqual((await verifyAttestation(missing, { fetch })).failures, ["missing_attestation"], String(missing));
    }
  });
});

describe("verifyAttestation: issuer and DID document", () => {
  test("a token whose iss is another issuer fails even with a valid signature", async () => {
    const jws = await signJws(claims({ iss: "did:web:evil.example" }), key.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["issuer_mismatch"]);
  });

  test("pinning another issuer resolves THAT issuer's DID document", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const { fetch, calls } = mockFetch(() => json(404, { error: "not_found" }));
    const v = await verifyAttestation(jws, { fetch, issuer: "did:web:other.example" });
    assert.deepEqual(calls.map((c) => c.url), ["https://other.example/.well-known/did.json"]);
    assert.deepEqual(v.failures, ["did_resolution_failed", "issuer_mismatch"]);
  });

  test("a DID document whose id is not the issuer is rejected", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk, { did: "did:web:evil.example" })).fetch });
    assert.deepEqual(v.failures, ["did_document_id_mismatch"]);
  });

  test("DID resolution failures are reported, not cached, and never throw", async () => {
    const jws = await signJws(claims(), key.privateKey);
    let n = 0;
    const { fetch } = mockFetch(() => {
      n++;
      if (n === 1) throw new TypeError("fetch failed");
      if (n === 2) return json(500, { error: "internal_error" });
      if (n === 3) return new Response("<html>", { status: 200 });
      return json(200, didDocument(key.publicJwk));
    });
    for (let i = 0; i < 3; i++) assert.deepEqual((await verifyAttestation(jws, { fetch })).failures, ["did_resolution_failed"]);
    assert.equal((await verifyAttestation(jws, { fetch })).valid, true);
    assert.equal(n, 4);
  });

  test("a DID document that never arrives times out", async () => {
    const jws = await signJws(claims(), key.privateKey);
    const fetch = () => new Promise<never>(() => {});
    const v = await verifyAttestation(jws, { fetch, timeoutMs: 20 });
    assert.deepEqual(v.failures, ["did_resolution_failed"]);
  });

  test("the DID document is cached per fetch implementation (5 min) and clearDidCache drops it", async () => {
    const { fetch, calls } = didFetch(didDocument(key.publicJwk));
    const jws = await signJws(claims(), key.privateKey);
    await Promise.all([verifyAttestation(jws, { fetch }), verifyAttestation(jws, { fetch })]);
    await verifyAttestation(jws, { fetch });
    assert.equal(calls.length, 1, "concurrent and repeated verifications share one fetch");
    const other = didFetch(didDocument(key.publicJwk));
    await verifyAttestation(jws, { fetch: other.fetch });
    assert.equal(other.calls.length, 1, "another fetch implementation has its own cache");
    clearDidCache();
    await verifyAttestation(jws, { fetch });
    assert.equal(calls.length, 2);
  });

  test("didWebDocumentUrl follows the did:web method", () => {
    assert.equal(didWebDocumentUrl("did:web:x402check.xyz"), "https://x402check.xyz/.well-known/did.json");
    assert.equal(didWebDocumentUrl("did:web:example.com:user:alice"), "https://example.com/user/alice/did.json");
    assert.equal(didWebDocumentUrl("did:web:localhost%3A8443"), "https://localhost:8443/.well-known/did.json");
    for (const bad of ["did:key:z6Mk", "did:web:", "did:web:evil.com%2F@x", "did:web:-bad.com", "did:web:a..b", "did:web:ex ample.com"]) {
      assert.equal(didWebDocumentUrl(bad), null, bad);
    }
  });

  test("an issuer that is not did:web is unsupported", async () => {
    const jws = await signJws(claims({ iss: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }), key.privateKey);
    const v = await verifyAttestation(jws, { issuer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", fetch: didFetch({}).fetch });
    assert.deepEqual(v.failures, ["unsupported_issuer"]);
  });
});

describe("verifyAttestation: time claims", () => {
  test("an expired attestation fails (no leeway on exp)", async () => {
    const iat = nowSeconds() - 3601;
    const jws = await signJws(claims({ iat, exp: iat + 3600 }), key.privateKey);
    const v = await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch });
    assert.deepEqual(v.failures, ["expired"]);
  });

  test("missing exp or iat fails", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const noExp = claims();
    delete noExp.exp;
    assert.deepEqual((await verifyAttestation(await signJws(noExp, key.privateKey), { fetch })).failures, ["missing_exp"]);
    const noIat = claims();
    delete noIat.iat;
    assert.deepEqual((await verifyAttestation(await signJws(noIat, key.privateKey), { fetch })).failures, ["missing_iat"]);
  });

  test("iat up to 5 minutes in the future is tolerated, beyond is not", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const ok = await signJws(claims({ iat: nowSeconds() + 240 }), key.privateKey);
    assert.equal((await verifyAttestation(ok, { fetch })).valid, true);
    const future = await signJws(claims({ iat: nowSeconds() + 400 }), key.privateKey);
    assert.deepEqual((await verifyAttestation(future, { fetch })).failures, ["iat_in_future"]);
  });

  test("nbf in the future fails", async () => {
    const jws = await signJws(claims({ nbf: nowSeconds() + 3000 }), key.privateKey);
    assert.deepEqual((await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch })).failures, ["not_yet_valid"]);
  });

  test("an invalid `now` fails closed instead of disabling the time checks", async () => {
    const iat = nowSeconds() - 7200;
    const expired = await signJws(claims({ iat, exp: iat + 3600 }), key.privateKey);
    const { fetch } = didFetch(didDocument(key.publicJwk));
    for (const now of [Number.NaN, new Date("not a date"), Number.POSITIVE_INFINITY]) {
      assert.deepEqual((await verifyAttestation(expired, { fetch, now })).failures, ["invalid_time"], String(now));
    }
  });

  test("`now` sets the verification time (Date or epoch ms)", async () => {
    const iat = 1_789_000_000;
    const jws = await signJws(claims({ iat, exp: iat + 3600 }), key.privateKey);
    const { fetch } = didFetch(didDocument(key.publicJwk));
    assert.equal((await verifyAttestation(jws, { fetch, now: new Date((iat + 60) * 1000) })).valid, true);
    assert.equal((await verifyAttestation(jws, { fetch, now: (iat + 60) * 1000 })).valid, true);
    assert.deepEqual((await verifyAttestation(jws, { fetch, now: (iat + 3600) * 1000 })).failures, ["expired"]);
  });

  test("claims of the wrong type are rejected", async () => {
    const jws = await signJws(claims({ score: "95", tier: "safe" }), key.privateKey);
    assert.deepEqual((await verifyAttestation(jws, { fetch: didFetch(didDocument(key.publicJwk)).fetch })).failures, ["invalid_claims"]);
  });
});

describe("verifyAttestation: binding to a request (replay limits)", () => {
  test("interaction must be the expected one (null: none)", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const permit = await signJws(claims({ interaction: "permit_signature" }), key.privateKey);
    assert.equal((await verifyAttestation(permit, { fetch, interaction: "permit_signature" })).valid, true);
    assert.deepEqual((await verifyAttestation(permit, { fetch, interaction: "native_transfer" })).failures, ["interaction_mismatch"]);
    assert.deepEqual((await verifyAttestation(permit, { fetch, interaction: null })).failures, ["interaction_mismatch"]);
    const none = claims();
    delete none.interaction;
    assert.equal((await verifyAttestation(await signJws(none, key.privateKey), { fetch, interaction: null })).valid, true);
    assert.deepEqual((await verifyAttestation(await signJws(none, key.privateKey), { fetch, interaction: "token_approval" })).failures, ["interaction_mismatch"]);
  });

  test("payment fields must match the signed payment claim (pay_to canonical, network aliases skipped)", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const payment = { network: "eip155:8453", pay_to: EVM, amount: "1000000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", resource: "https://api.merchant.example/report" };
    const jws = await signJws(claims({ payment }), key.privateKey);
    const upper = EVM.toUpperCase().replace("0X", "0x");
    assert.equal((await verifyAttestation(jws, { fetch, payment: { ...payment, network: "base", pay_to: upper } })).valid, true);
    assert.equal((await verifyAttestation(jws, { fetch, payment: { amount: "1000000" } })).valid, true, "only the given fields are compared");
    assert.deepEqual((await verifyAttestation(jws, { fetch, payment: { amount: "2000000" } })).failures, ["payment_mismatch"]);
    assert.deepEqual((await verifyAttestation(jws, { fetch, payment: { network: "eip155:1" } })).failures, ["payment_mismatch"]);
    assert.deepEqual((await verifyAttestation(jws, { fetch, payment: { pay_to: "0x0000000000000000000000000000000000000001" } })).failures, ["payment_mismatch"]);
    const unbound = await signJws(claims(), key.privateKey);
    assert.deepEqual((await verifyAttestation(unbound, { fetch, payment: { amount: "1000000" } })).failures, ["payment_mismatch"]);
    assert.equal((await verifyAttestation(unbound, { fetch, payment: {} })).valid, true, "an empty expectation binds nothing");
  });

  test("maxAgeSeconds rejects an attestation issued too long ago (with the clock-skew allowance)", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const old = await signJws(claims({ iat: nowSeconds() - 700 }), key.privateKey);
    assert.deepEqual((await verifyAttestation(old, { fetch, maxAgeSeconds: 300 })).failures, ["stale"]);
    assert.equal((await verifyAttestation(old, { fetch })).valid, true, "without maxAgeSeconds only exp applies");
    const skewed = await signJws(claims({ iat: nowSeconds() - 500 }), key.privateKey);
    assert.equal((await verifyAttestation(skewed, { fetch, maxAgeSeconds: 300 })).valid, true, "a verifier clock up to 5 minutes fast is tolerated");
    assert.equal((await verifyAttestation(await signJws(claims(), key.privateKey), { fetch, maxAgeSeconds: 300 })).valid, true);
  });

  test("request binding: every signed, bindable field must match the request that was sent", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const payment = { network: "eip155:8453", pay_to: EVM, amount: "1000000" };
    const signed = claims({
      aud: "https://merchant.example/api",
      interaction: "permit_signature",
      payment,
      checks: {
        sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
        domain: { host: "app.uniswap.org", impersonation: "none" },
        onchain: { status: "ok", network: "eip155:8453", activity: "some" },
        simulation: { status: "ok", network: "eip155:8453" },
        model: "jev-wallet-risk/v6",
      },
    });
    const jws = await signJws(signed, key.privateKey);
    const request = {
      wallet: EVM.toUpperCase().replace("0X", "0x"),
      chain: "base",
      domain: "https://App.Uniswap.org/swap?inputCurrency=ETH",
      aud: "https://merchant.example/api",
      interaction: { type: "permit_signature" as const, unlimited: true },
      payment: { network: "base", pay_to: EVM, amount: "1000000" },
      transaction: { from: EVM, to: EVM, data: "0x" },
      context: "not signed in a comparable form",
    };
    const ok = await verifyAttestation(jws, { fetch, request });
    assert.deepEqual(ok.failures, []);
    const mismatches: Array<[Record<string, unknown>, string]> = [
      [{ domain: undefined }, "domain_mismatch"],
      [{ domain: "app-uniswap.org" }, "domain_mismatch"],
      [{ chain: "ethereum" }, "chain_mismatch"],
      [{ chain: undefined }, "chain_mismatch"],
      [{ transaction: undefined }, "transaction_mismatch"],
      [{ interaction: undefined }, "interaction_mismatch"],
      [{ payment: undefined }, "payment_mismatch"],
      [{ aud: undefined }, "audience_mismatch"],
      [{ wallet: SOL }, "subject_mismatch"],
    ];
    for (const [change, failure] of mismatches) {
      const v = await verifyAttestation(jws, { fetch, request: { ...request, ...change } as typeof request });
      assert.deepEqual(v.failures, [failure], JSON.stringify(change));
    }
    assert.equal((await verifyAttestation(jws, { fetch, request: { ...request, chain: "some-future-alias" } })).valid, true, "an alias this client does not know is not compared");
    assert.equal((await verifyAttestation(jws, { fetch, request: { ...request, wallet: `eip155:8453:${EVM}`, chain: undefined } })).valid, true, "a CAIP-10 wallet carries its chain");
  });

  test("request binding: a transaction but no simulation, or a simulation nobody asked for, fails; the sanctions short-circuit does not", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const base = claims();
    const stripped = await signJws({ ...base, interaction: undefined }, key.privateKey);
    const request = { wallet: EVM, chain: "eip155:1", transaction: { from: EVM, data: "0x" } };
    assert.deepEqual((await verifyAttestation(stripped, { fetch, request })).failures, ["transaction_mismatch"]);
    const sanctioned = await signJws({ ...base, interaction: undefined, tier: "critical", score: 0, checks: { ...(base.checks as object), model: "skipped" } }, key.privateKey);
    assert.equal((await verifyAttestation(sanctioned, { fetch, request })).valid, true, "a deterministic sanctions verdict runs nothing else");
    const simulated = await signJws({ ...base, interaction: undefined, checks: { ...(base.checks as object), simulation: { status: "ok" } } }, key.privateKey);
    assert.deepEqual((await verifyAttestation(simulated, { fetch, request: { wallet: EVM, chain: "eip155:1" } })).failures, ["transaction_mismatch"]);
  });

  test("request_hash (v0.3): every field as sent is bound, context and interaction.unlimited included", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const request = {
      wallet: EVM,
      chain: "eip155:1",
      context: "Tool output: approve 0x7a3e… for the swap",
      interaction: { type: "permit_signature" as const, unlimited: true },
    };
    const signed = claims({ request_hash: await requestHash(request) });
    const jws = await signJws(signed, key.privateKey);
    assert.deepEqual((await verifyAttestation(jws, { fetch, request })).failures, []);
    // An intermediary stripped the injected context, or the unlimited flag, before forwarding:
    const stripped = await verifyAttestation(jws, { fetch, request: { ...request, context: undefined } });
    assert.deepEqual(stripped.failures, ["request_mismatch"]);
    const limited = await verifyAttestation(jws, { fetch, request: { ...request, interaction: { type: "permit_signature" } } });
    assert.deepEqual(limited.failures, ["request_mismatch"]);
    // Without `request`, nothing is compared (a relying party that only knows the token).
    assert.equal((await verifyAttestation(jws, { fetch })).valid, true);
  });

  test("request_hash: absent (older provider) is skipped; present but not a string fails", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const request = { wallet: EVM, chain: "eip155:1", interaction: { type: "permit_signature" as const } };
    const older = await signJws(claims(), key.privateKey);
    assert.equal((await verifyAttestation(older, { fetch, request })).valid, true);
    const odd = await signJws(claims({ request_hash: 42 }), key.privateKey);
    assert.deepEqual((await verifyAttestation(odd, { fetch, request })).failures, ["request_mismatch"]);
  });

  test("request_hash for a batch binds each attestation to its own item", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const items = [
      { wallet: EVM, chain: "eip155:1", interaction: { type: "permit_signature" as const } },
      { wallet: EVM, chain: "eip155:1", interaction: { type: "permit_signature" as const }, context: "second item" },
    ];
    const second = await signJws(claims({ request_hash: await requestHash(items[1]!) }), key.privateKey);
    assert.equal((await verifyAttestation(second, { fetch, request: items[1] })).valid, true);
    assert.deepEqual((await verifyAttestation(second, { fetch, request: items[0] })).failures, ["request_mismatch"]);
  });

  test("payment: null and aud: null require the claim to be absent", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const paid = await signJws(claims({ payment: { amount: "1" } }), key.privateKey);
    assert.deepEqual((await verifyAttestation(paid, { fetch, payment: null })).failures, ["payment_mismatch"]);
    assert.equal((await verifyAttestation(await signJws(claims(), key.privateKey), { fetch, payment: null })).valid, true);
  });
});

describe("verifyAttestation: audience and subject", () => {
  test("aud must match when required", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const jws = await signJws(claims({ aud: "https://merchant.example/api" }), key.privateKey);
    assert.equal((await verifyAttestation(jws, { fetch, aud: "https://merchant.example/api" })).valid, true);
    assert.deepEqual((await verifyAttestation(jws, { fetch, aud: "https://other.example/api" })).failures, ["audience_mismatch"]);
    const noAud = await signJws(claims(), key.privateKey);
    assert.deepEqual((await verifyAttestation(noAud, { fetch, aud: "https://merchant.example/api" })).failures, ["audience_mismatch"]);
    const listAud = await signJws(claims({ aud: ["https://a.example", "https://merchant.example/api"] }), key.privateKey);
    assert.equal((await verifyAttestation(listAud, { fetch, aud: "https://merchant.example/api" })).valid, true);
  });

  test("sub mismatch fails; EVM comparison is case-insensitive", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const jws = await signJws(claims(), key.privateKey);
    assert.equal((await verifyAttestation(jws, { fetch, sub: EVM.toUpperCase().replace("0X", "0x") })).valid, true);
    assert.deepEqual((await verifyAttestation(jws, { fetch, sub: "0x0000000000000000000000000000000000000001" })).failures, ["subject_mismatch"]);
    assert.deepEqual((await verifyAttestation(jws, { fetch, sub: "not an address" })).failures, ["subject_mismatch"]);
  });

  test("base58 subjects are case-SENSITIVE: a case-flipped Solana address does not match", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const jws = await signJws(claims({ sub: SOL }), key.privateKey);
    assert.equal((await verifyAttestation(jws, { fetch, sub: SOL })).valid, true);
    const flipped = flipBase58Case(SOL);
    assert.ok(parseSubject(flipped)?.format === "base58", "the flipped string is itself a valid base58 address");
    assert.deepEqual((await verifyAttestation(jws, { fetch, sub: flipped })).failures, ["subject_mismatch"]);
  });

  test("aud: null requires that the token carries no audience", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    assert.equal((await verifyAttestation(await signJws(claims(), key.privateKey), { fetch, aud: null })).valid, true);
    const withAud = await signJws(claims({ aud: "https://merchant.example/api" }), key.privateKey);
    assert.deepEqual((await verifyAttestation(withAud, { fetch, aud: null })).failures, ["audience_mismatch"]);
  });

  test("a CAIP-10 subject matches the bare address (and vice versa)", async () => {
    const { fetch } = didFetch(didDocument(key.publicJwk));
    const caip = await signJws(claims({ sub: `eip155:8453:${EVM.toUpperCase().replace("0X", "0x")}` }), key.privateKey);
    assert.equal((await verifyAttestation(caip, { fetch, sub: EVM })).valid, true);
    const bare = await signJws(claims({ sub: SOL }), key.privateKey);
    assert.equal((await verifyAttestation(bare, { fetch, sub: `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${SOL}` })).valid, true);
  });
});

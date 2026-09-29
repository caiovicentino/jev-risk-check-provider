import { test } from "node:test";
import assert from "node:assert";
import { generateKeyPair, signJws, verifyJws, inputHash } from "../src/jws.js";

test("jws roundtrip verifies and returns claims", () => {
  const kp = generateKeyPair("jev-attest-v1");
  const claims = {
    iss: "did:web:paysol.local",
    sub: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    score: 87,
    tier: "low",
    iat: 1_789_000_000,
    exp: 1_789_003_600,
    categories: ["intent_risk"],
  };
  const jws = signJws(claims, kp.publicJwk.kid, kp.privatePem);
  const verified = verifyJws(jws, kp.publicJwk);
  assert.ok(verified);
  assert.equal(verified.score, 87);
  assert.equal(verified.tier, "low");
  assert.equal(verified.iss, "did:web:paysol.local");
});

test("tampered payload fails verification", () => {
  const kp = generateKeyPair("jev-attest-v1");
  const jws = signJws(
    { iss: "did:web:paysol.local", sub: "w", score: 90, tier: "low", iat: 1, exp: 2 },
    kp.publicJwk.kid,
    kp.privatePem,
  );
  const parts = jws.split(".");
  const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
  payload.score = 100;
  const tampered = `${parts[0]}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${parts[2]}`;
  assert.equal(verifyJws(tampered, kp.publicJwk), null);
});

test("foreign key fails verification", () => {
  const kp1 = generateKeyPair("jev-attest-v1");
  const kp2 = generateKeyPair("other-kid");
  const jws = signJws(
    { iss: "did:web:paysol.local", sub: "w", score: 50, tier: "high", iat: 1, exp: 2 },
    kp1.publicJwk.kid,
    kp1.privatePem,
  );
  assert.equal(verifyJws(jws, kp2.publicJwk), null);
});

test("malformed jws returns null", () => {
  const kp = generateKeyPair("jev-attest-v1");
  assert.equal(verifyJws("not.a.jws", kp.publicJwk), null);
  assert.equal(verifyJws("a.b.c.d", kp.publicJwk), null);
});

test("input hash is deterministic and key order insensitive", () => {
  const a = inputHash({ wallet: "w1", chain: "solana", domain: null });
  const b = inputHash({ chain: "solana", wallet: "w1", domain: null });
  assert.equal(a, b);
  assert.equal(a.length, 64);
});

test("signing accepts both SEC1 (production secret format) and PKCS#8 PEM keys", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pub = { kty: "EC" as const, crv: "P-256" as const, x: jwk.x, y: jwk.y, kid: "k", alg: "ES256" as const, use: "sig" as const };
  for (const type of ["sec1", "pkcs8"] as const) {
    const pem = privateKey.export({ format: "pem", type }).toString();
    const jws = signJws({ iss: "did:web:x", sub: "w", score: 1, tier: "low", iat: 1, exp: 2 }, "k", pem);
    assert.ok(verifyJws(jws, pub), type);
  }
});

// Upstream review (x402-foundation/x402#3597): the v5 hash used a replacer array, so
// nested keys outside the top-level whitelist vanished. These pin the JCS behaviour.
test("input hash: nested value changes change the hash (x402#3597 example)", async () => {
  assert.notEqual(inputHash({ context: { amount: 1 } }), inputHash({ context: { amount: 999 } }));
  assert.notEqual(inputHash({ payment: { pay_to: "a", amount: "1" } }), inputHash({ payment: { pay_to: "a", amount: "2" } }));
});

test("input hash: nested key order does not matter, array order does", async () => {
  assert.equal(inputHash({ a: { x: 1, y: { p: 1, q: 2 } } }), inputHash({ a: { y: { q: 2, p: 1 }, x: 1 } }));
  assert.notEqual(inputHash({ q: ["a", "b"] }), inputHash({ q: ["b", "a"] }));
  assert.equal(inputHash({ q: [{ b: 1, a: 2 }] }), inputHash({ q: [{ a: 2, b: 1 }] }));
});

test("canonical JSON follows RFC 8785 (JCS): official sample + numeric edge cases", async () => {
  const { canonicalJson } = await import("../src/jws.js");
  // RFC 8785 §3.2.2 sample input and its canonical form
  const sample = JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}');
  assert.equal(canonicalJson(sample), '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  assert.equal(canonicalJson({ a: 1 }), canonicalJson({ a: 1.0 }));
  assert.equal(canonicalJson({ a: -0 }), '{"a":0}');
  assert.equal(canonicalJson({ a: 1e21 }), '{"a":1e+21}');
  assert.equal(canonicalJson({ a: 0.1 + 0.2 }), '{"a":0.30000000000000004}');
  assert.equal(canonicalJson({ "é": 1, e: 2, "😀": 3 }), '{"e":2,"é":1,"😀":3}'); // UTF-16 code-unit order
  assert.throws(() => canonicalJson({ a: Number.NaN }));
  assert.throws(() => canonicalJson({ a: Number.POSITIVE_INFINITY }));
  assert.throws(() => canonicalJson({ a: 10n }));
});

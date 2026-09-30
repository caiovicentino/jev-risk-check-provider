// Attestation keys are pinned (RFC 7638 thumbprints) in every verification the server makes:
// x402check_check, x402check_pay's guard and x402check_verify_attestation. By default the pins
// are @x402check/client's X402CHECK_KEY_THUMBPRINTS for did:web:x402check.xyz, so a DID document
// serving any other key (a compromised domain or deployment) is refused.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { X402CHECK_KEY_THUMBPRINTS } from "@x402check/client";
import { generatePrivateKey } from "viem/accounts";
import { configFromEnv, createX402CheckServer } from "../src/server.js";
import { json, KID, makeIssuer, router, sign, SPENDER, CHECKS, ISSUER, type Issuer } from "./helpers.js";
import { call, errorCode, RESOURCE, session, TOKEN, world } from "./merchant.js";

const BIN = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const OTHER_KEY = "A".repeat(43);

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

function claims(iss = ISSUER): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss, sub: SPENDER, score: 88, tier: "low", iat: now, exp: now + 3600, jti: "7d0f3a52-1c4b-4e8a-9f6d-2b3c4d5e6f70", categories: [], input_hash: "b".repeat(64), checks: CHECKS };
}

describe("attestation keys are pinned", () => {
  test("by default, x402check's own keys: a DID document serving another key is refused by every tool", async () => {
    assert.ok(!X402CHECK_KEY_THUMBPRINTS.includes(issuer.thumbprint));
    const w = world(issuer);
    // No pinnedKeys: the server's default (the production key), not the fixture key the DID document serves.
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, payerKey: generatePrivateKey(), pinnedKeys: undefined });
    try {
      const check = await call(s.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.equal(check.structuredContent?.action, "not_verified");
      assert.deepEqual((check.structuredContent?.attestation as { failures: string[] }).failures, ["key_not_pinned"]);
      assert.match(check.text, /attestation failed verification \(key_not_pinned\)/);

      const verify = await call(s.client, "x402check_verify_attestation", { jws: await sign(issuer, claims()) });
      assert.equal(verify.structuredContent?.valid, false);
      assert.match(verify.text, /^x402check attestation: INVALID \(key_not_pinned\)\. Do not rely on it\./);

      const pay = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.deepEqual([pay.structuredContent?.outcome, pay.structuredContent?.action], ["refused", "not_verified"]);
      assert.match(pay.text, /key_not_pinned/);
      assert.equal(w.payments().length, 0, "nothing is signed on an unpinned key");
    } finally {
      await s.close();
    }
  });

  test("X402CHECK_PINNED_KEYS lists the keys accepted", async () => {
    assert.deepEqual(configFromEnv({ X402CHECK_PINNED_KEYS: ` ${issuer.thumbprint} , ${OTHER_KEY} ` }).pinnedKeys, [issuer.thumbprint, OTHER_KEY]);
    assert.equal("pinnedKeys" in configFromEnv({ X402CHECK_PINNED_KEYS: "  " }), false, "blank: the default");
    const jws = await sign(issuer, claims());
    for (const [pins, valid] of [
      [`${OTHER_KEY},${issuer.thumbprint}`, true],
      [OTHER_KEY, false],
    ] as const) {
      const s = await session({ ...configFromEnv({ X402CHECK_PINNED_KEYS: pins }), fetch: router(issuer, () => json(500, {})).fetch });
      try {
        const r = await call(s.client, "x402check_verify_attestation", { jws });
        assert.equal(r.structuredContent?.valid, valid, pins);
        if (!valid) assert.deepEqual(r.structuredContent?.failures, ["key_not_pinned"]);
      } finally {
        await s.close();
      }
    }
  });

  test("another issuer is pinned only with a list (as the guard does); with one, it is enforced", async () => {
    const other = "did:web:provider.example";
    const doc = { id: other, verificationMethod: [{ id: `${other}#${KID}`, type: "JsonWebKey2020", controller: other, publicKeyJwk: issuer.jwk }], assertionMethod: [`${other}#${KID}`] };
    const fetch = async (url: string) => (url === "https://provider.example/.well-known/did.json" ? json(200, doc) : json(500, {}));
    const jws = await sign(issuer, claims(other));
    for (const [pinnedKeys, valid] of [
      [undefined, true],
      [[issuer.thumbprint], true],
      [[OTHER_KEY], false],
    ] as const) {
      const s = await session({ issuer: other, fetch: fetch as never, pinnedKeys });
      try {
        const r = await call(s.client, "x402check_verify_attestation", { jws });
        assert.equal(r.structuredContent?.valid, valid, `${JSON.stringify(pinnedKeys)}: ${r.text}`);
        if (!valid) assert.deepEqual(r.structuredContent?.failures, ["key_not_pinned"]);
      } finally {
        await s.close();
      }
    }
  });

  test("an unusable list fails at startup; pinning cannot be switched off from the environment", () => {
    for (const env of ["not-a-thumbprint", ",", "false", "off", `${"A".repeat(42)}`]) {
      assert.throws(() => createX402CheckServer(configFromEnv({ X402CHECK_PINNED_KEYS: env })), /X402CHECK_PINNED_KEYS must be comma-separated RFC 7638 SHA-256 key thumbprints/, env);
    }
    assert.throws(() => createX402CheckServer({ pinnedKeys: [] }), /X402CHECK_PINNED_KEYS/);
    assert.doesNotThrow(() => createX402CheckServer({ pinnedKeys: [OTHER_KEY] }));
    const run = spawnSync(process.execPath, [BIN], { encoding: "utf8", env: { ...process.env, X402CHECK_PINNED_KEYS: "off" }, input: "" });
    assert.notEqual(run.status, 0);
    assert.equal(run.stdout, "", "stdout is reserved for MCP messages");
    assert.match(run.stderr, /x402check-mcp: X402CHECK_PINNED_KEYS must be comma-separated RFC 7638 SHA-256 key thumbprints/);
  });

  test("a server pinned to the fixture key still pays (the key is checked, then the payment signed)", async () => {
    const w = world(issuer);
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, payerKey: generatePrivateKey(), pinnedKeys: [issuer.thumbprint] });
    try {
      const r = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.equal(r.structuredContent?.outcome, "paid", r.text);
      assert.equal(errorCode(r), undefined);
    } finally {
      await s.close();
    }
  });
});

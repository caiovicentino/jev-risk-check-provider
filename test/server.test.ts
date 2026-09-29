import { test } from "node:test";
import assert from "node:assert";
import { startServer } from "../src/server.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair, verifyJws } from "../src/jws.js";
import type { Answer, RiskCheckDiscovery, RiskCheckResult, SystemOneResponse } from "../src/types.js";

const CANNED: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.05 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.03 },
  risky_domain: { type: "noul", noul: 0.01 },
  guard_bypass_attempt: { type: "noul", noul: 0.01 },
  risk_class: {
    type: "choice",
    choice: "benign",
    probabilities: { benign: 0.95, automated_abuse: 0.03, fraud_signal: 0.02, unclassifiable: 0.0 },
    confidence: 0.88,
  },
  trust: {
    type: "score",
    score: 3.8,
    legend: { "0": "a", "1": "b", "2": "c", "3": "d", "4": "e" },
    probabilities: { "0": 0, "1": 0, "2": 0.05, "3": 0.35, "4": 0.6 },
    confidence: 0.85,
  },
};

function mockFetch(body: unknown, status = 200) {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch;
}

async function start(port: number, jev: Provider["config"]["jev"] | null) {
  return startServer({
    provider: new Provider({ host: "paysol.test", keyPair: generateKeyPair("jev-attest-v1"), jev }),
    port,
  });
}

test("serves discovery document", async () => {
  const srv = await start(18081, null);
  try {
    const res = await fetch("http://127.0.0.1:18081/.well-known/risk-check.json");
    assert.equal(res.status, 200);
    const doc = (await res.json()) as RiskCheckDiscovery;
    assert.equal(doc.endpoint, "/v1/risk-check");
    assert.equal(doc.batch_endpoint, "/v1/risk-check/batch");
    assert.equal(doc.attestation?.algorithm, "ES256");
    assert.ok(doc.chains_supported?.includes("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
    assert.equal(doc.name, "x402check");
    assert.ok(doc.data_sources?.ofac_sdn?.includes("SDN"));
  } finally {
    await srv.close();
  }
});

test("serves jwks with matching kid", async () => {
  const srv = await start(18082, null);
  try {
    const res = await fetch("http://127.0.0.1:18082/.well-known/jwks.json");
    assert.equal(res.status, 200);
    const jwks = (await res.json()) as { keys: Array<{ kid: string; kty: string; crv: string }> };
    assert.equal(jwks.keys[0]?.kid, "jev-attest-v1");
    assert.equal(jwks.keys[0]?.kty, "EC");
    assert.equal(jwks.keys[0]?.crv, "P-256");
  } finally {
    await srv.close();
  }
});

test("fail-closed without jev: checked false", async () => {
  const srv = await start(18083, null);
  try {
    const res = await fetch("http://127.0.0.1:18083/v1/risk-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", chain: "solana" }),
    });
    assert.equal(res.status, 200);
    const result = (await res.json()) as RiskCheckResult;
    assert.equal(result.checked, false);
    assert.equal(result.score, undefined);
    assert.equal(result.jws, undefined);
  } finally {
    await srv.close();
  }
});

test("risk-check with mock jev returns scored result with verifiable jws", async () => {
  const jev = new (await import("../src/jev.js")).JevClient({
    apiKey: "test",
    fetchImpl: mockFetch({
      model: "jev-1.13.0",
      answers: CANNED,
      usage: { input_tokens: 300, output_tokens: 20 },
    } satisfies SystemOneResponse),
  });
  const srv = await start(18084, jev);
  try {
    const res = await fetch("http://127.0.0.1:18084/v1/risk-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        chain: "solana",
        domain: "api.merchant-labs.com",
        context: "agent pays $0.05 for API access",
        aud: "https://resource.example.com/data",
      }),
    });
    assert.equal(res.status, 200);
    const result = (await res.json()) as RiskCheckResult;
    assert.equal(result.checked, true);
    assert.equal(result.tier, "low");
    assert.ok((result.score ?? 0) >= 80);
    assert.ok(result.jws);
    const claims = verifyJws(result.jws as string, { kty: "EC", crv: "P-256", x: "", y: "", kid: "jev-attest-v1", alg: "ES256", use: "sig" });
    assert.equal(claims, null);
  } finally {
    await srv.close();
  }
});

test("jws verifies against served jwks", async () => {
  const { JevClient } = await import("../src/jev.js");
  const jev = new JevClient({
    apiKey: "test",
    fetchImpl: mockFetch({ model: "jev-1.13.0", answers: CANNED, usage: { input_tokens: 1, output_tokens: 1 } }),
  });
  const srv = await start(18085, jev);
  try {
    const check = await fetch("http://127.0.0.1:18085/v1/risk-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }),
    });
    const result = (await check.json()) as RiskCheckResult;
    const jwksRes = await fetch("http://127.0.0.1:18085/.well-known/jwks.json");
    const jwks = (await jwksRes.json()) as { keys: Array<{ kty: string; crv: string; x: string; y: string; kid: string; alg: string; use: string }> };
    const claims = verifyJws(result.jws as string, jwks.keys[0] as never);
    assert.ok(claims);
    assert.equal(claims.sub, "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    assert.equal(claims.iss, "did:web:paysol.test");
  } finally {
    await srv.close();
  }
});

test("invalid request returns 422", async () => {
  const srv = await start(18086, null);
  try {
    const res = await fetch("http://127.0.0.1:18086/v1/risk-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "no-wallet.com" }),
    });
    assert.equal(res.status, 422);
  } finally {
    await srv.close();
  }
});

test("batch endpoint processes multiple requests", async () => {
  const { JevClient } = await import("../src/jev.js");
  const jev = new JevClient({
    apiKey: "test",
    fetchImpl: mockFetch({ model: "jev-1.13.0", answers: CANNED, usage: { input_tokens: 1, output_tokens: 1 } }),
  });
  const srv = await start(18087, jev);
  try {
    const res = await fetch("http://127.0.0.1:18087/v1/risk-check/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requests: [
          { wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", chain: "solana" },
          { wallet: "4Nd1mBQtrMJVYVfKf2PJz9URjc7WJ9DjXFGwS4tCryhe", chain: "solana" },
        ],
      }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { results: RiskCheckResult[] };
    assert.equal(body.results.length, 2);
    assert.ok(body.results.every((r) => r.checked));
  } finally {
    await srv.close();
  }
});

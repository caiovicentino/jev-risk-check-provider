import { discoveryDocument, Provider } from "./provider.js";
import { jwksDocument } from "./jws.js";
import { landingPage, OG_PNG_B64 } from "./landing.js";
import type { RiskCheckRequest } from "./types.js";

const MAX_BATCH = 25;

export type HandlerDeps = {
  provider: Provider;
};

function validateRequest(body: unknown): RiskCheckRequest | null {
  if (!body || typeof body !== "object") return null;
  const obj = body as Record<string, unknown>;
  if (typeof obj.wallet !== "string" || obj.wallet.trim().length === 0) return null;
  if (obj.wallet.trim().length > 128) return null;
  for (const field of ["chain", "domain", "context", "aud"] as const) {
    if (obj[field] !== undefined && typeof obj[field] !== "string") return null;
  }
  let screening: RiskCheckRequest["screening"];
  if (obj.screening && typeof obj.screening === "object") {
    const s = obj.screening as Record<string, unknown>;
    if (s.sanctions === "clean" || s.sanctions === "flagged" || s.sanctions === "unknown") {
      screening = { sanctions: s.sanctions };
    }
  }
  let authorization: RiskCheckRequest["authorization"];
  if (obj.authorization && typeof obj.authorization === "object") {
    const a = obj.authorization as Record<string, unknown>;
    if (typeof a.pre_authorized === "boolean") {
      authorization = { pre_authorized: a.pre_authorized, source: typeof a.source === "string" ? a.source : undefined };
    }
  }
  return {
    wallet: obj.wallet.trim(),
    chain: obj.chain as string | undefined,
    domain: obj.domain as string | undefined,
    context: obj.context as string | undefined,
    aud: obj.aud as string | undefined,
    screening,
    authorization,
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function readJson(req: Request): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

function didDocument(host: string, publicJwk: Record<string, unknown>): Record<string, unknown> {
  const did = `did:web:${host}`;
  const keyId = `${did}#${publicJwk.kid ?? "jev-attest-v1"}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
    assertionMethod: [keyId],
    authentication: [keyId],
    service: [
      {
        id: `${did}#risk-check`,
        type: "RiskCheckProvider",
        serviceEndpoint: `https://${host}/v1/risk-check`,
      },
      {
        id: `${did}#jwks`,
        type: "JsonWebKey",
        serviceEndpoint: `https://${host}/.well-known/jwks.json`,
      },
      {
        id: `${did}#discovery`,
        type: "RiskCheckDiscovery",
        serviceEndpoint: `https://${host}/.well-known/risk-check.json`,
      },
    ],
  };
}

export function createHandler(deps: HandlerDeps): (req: Request) => Promise<Response> {
  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "GET" && path === "/.well-known/risk-check.json") {
      return json(200, discoveryDocument(deps.provider.host));
    }
    if (req.method === "GET" && path === "/.well-known/jwks.json") {
      return json(200, jwksDocument(deps.provider.keyPair.publicJwk.kid, deps.provider.keyPair.publicJwk));
    }
    if (req.method === "GET" && path === "/.well-known/did.json") {
      return json(200, didDocument(deps.provider.host, deps.provider.keyPair.publicJwk as unknown as Record<string, unknown>));
    }
    if (req.method === "POST" && path === "/v1/risk-check") {
      const parsed = validateRequest(await readJson(req));
      if (!parsed) return json(422, { error: "invalid_request" });
      const evaluation = await deps.provider.evaluate(parsed);
      return json(200, evaluation.result);
    }
    if (req.method === "POST" && path === "/v1/risk-check/batch") {
      const body = await readJson(req);
      if (!body || typeof body !== "object" || !Array.isArray((body as { requests?: unknown }).requests)) {
        return json(422, { error: "invalid_request" });
      }
      const requests = (body as { requests: unknown[] }).requests
        .map((r) => validateRequest(r))
        .filter((r): r is RiskCheckRequest => r !== null);
      if (requests.length === 0) return json(422, { error: "invalid_request" });
      if (requests.length > MAX_BATCH) return json(413, { error: "batch_too_large", max: MAX_BATCH });
      const results = await Promise.all(requests.map((r) => deps.provider.evaluate(r)));
      return json(200, { results: results.map((e) => e.result) });
    }
    if (req.method === "GET" && path === "/" ) {
      const accept = req.headers.get("accept") ?? "";
      if (accept.includes("text/html")) {
        return new Response(landingPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      return json(200, discoveryDocument(deps.provider.host));
    }
    if (req.method === "GET" && path === "/og.png") {
      return new Response(Uint8Array.from(atob(OG_PNG_B64), (ch) => ch.charCodeAt(0)), {
        status: 200,
        headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" },
      });
    }
    if (req.method === "GET" && path === "/healthz") {
      return json(200, { ok: true });
    }
    return json(404, { error: "not_found" });
  };
}

import { discoveryDocument, Provider, type PricingInfo } from "./provider.js";
import { jwksDocument } from "./jws.js";
import { landingPage, OG_PNG_B64 } from "./landing.js";
import { ICON_PNG_B64 } from "./icon.js";
import { validateBatch, validateRequest } from "./validate.js";

export type HandlerDeps = {
  provider: Provider;
  pricing?: PricingInfo | undefined;
};

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

    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/risk-check.json") {
      return json(200, discoveryDocument(deps.provider.host, deps.pricing));
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/jwks.json") {
      return json(200, jwksDocument(deps.provider.keyPair.publicJwk.kid, deps.provider.keyPair.publicJwk));
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/did.json") {
      return json(200, didDocument(deps.provider.host, deps.provider.keyPair.publicJwk as unknown as Record<string, unknown>));
    }
    if (req.method === "POST" && path === "/v1/risk-check") {
      const v = validateRequest(await readJson(req));
      if (!v.ok) return json(422, { error: "invalid_request", field: v.field });
      const evaluation = await deps.provider.evaluate(v.value);
      return json(200, evaluation.result);
    }
    if (req.method === "POST" && path === "/v1/risk-check/batch") {
      const v = validateBatch(await readJson(req));
      if (!v.ok) return json(v.status, v.body);
      const results = await Promise.all(v.value.map((r) => deps.provider.evaluate(r)));
      return json(200, { results: results.map((e) => e.result) });
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/" ) {
      const accept = req.headers.get("accept") ?? "";
      if (accept.includes("text/html")) {
        return new Response(landingPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      return json(200, discoveryDocument(deps.provider.host, deps.pricing));
    }
    if (req.method === "GET" && path === "/icon.png") {
      return new Response(Uint8Array.from(atob(ICON_PNG_B64), (ch) => ch.charCodeAt(0)), {
        status: 200,
        headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" },
      });
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

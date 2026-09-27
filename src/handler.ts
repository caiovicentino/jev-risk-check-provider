import { discoveryDocument, Provider } from "./provider.js";
import { jwksDocument } from "./jws.js";
import type { RiskCheckRequest } from "./types.js";

export type HandlerDeps = {
  provider: Provider;
};

function validateRequest(body: unknown): RiskCheckRequest | null {
  if (!body || typeof body !== "object") return null;
  const obj = body as Record<string, unknown>;
  if (typeof obj.wallet !== "string" || obj.wallet.length === 0) return null;
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
    wallet: obj.wallet,
    chain: typeof obj.chain === "string" ? obj.chain : undefined,
    domain: typeof obj.domain === "string" ? obj.domain : undefined,
    context: typeof obj.context === "string" ? obj.context : undefined,
    aud: typeof obj.aud === "string" ? obj.aud : undefined,
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
      const results = await Promise.all(requests.map((r) => deps.provider.evaluate(r)));
      return json(200, { results: results.map((e) => e.result) });
    }
    if (req.method === "GET" && path === "/healthz") {
      return json(200, { ok: true });
    }
    return json(404, { error: "not_found" });
  };
}

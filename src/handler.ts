import { createHash } from "node:crypto";
import { discoveryDocument, Provider, type PricingInfo } from "./provider.js";
import { jwksDocument, publicJwkOf } from "./jws.js";
import { landingPage, OG_PNG_B64 } from "./landing.js";
import { FAVICON_ICO_B64, ICON_PNG_B64 } from "./icon.js";
import { validateBatch, validateRequest } from "./validate.js";

export type HandlerDeps = {
  provider: Provider;
  pricing?: PricingInfo | undefined;
  /** A next attestation key published ahead of a rotation: listed in jwks.json and did.json (its own kid). */
  nextPublicJwk?: Record<string, unknown> | undefined;
};

/** The site's one page (sitemaps.org). */
export function sitemap(host: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>https://${host}/</loc></url>\n</urlset>\n`;
}

/** How to report a vulnerability (RFC 9116). */
export const SECURITY_TXT = [
  "Contact: https://github.com/caiovicentino/jev-risk-check-provider/security/advisories/new",
  "Expires: 2027-09-30T00:00:00.000Z",
  "Policy: https://github.com/caiovicentino/jev-risk-check-provider/blob/main/SECURITY.md",
  "Canonical: https://x402check.xyz/.well-known/security.txt",
  "Preferred-Languages: en, pt",
  "",
].join("\n");

let landingCache: { html: string; csp: string } | null = null;
/**
 * The site and its Content-Security-Policy: its one inline script is allowed by hash, styles and
 * fonts from Google Fonts, the video from youtube-nocookie, Cloudflare's cookieless Web Analytics
 * beacon (injected by the zone), and nothing may frame the page.
 */
function landing(): { html: string; csp: string } {
  if (landingCache) return landingCache;
  const html = landingPage();
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => `'sha256-${createHash("sha256").update(m[1] as string).digest("base64")}'`);
  const csp = [
    "default-src 'none'",
    `script-src ${[...scripts, "https://static.cloudflareinsights.com"].join(" ")}`,
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://cloudflareinsights.com",
    "frame-src https://www.youtube-nocookie.com",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  landingCache = { html, csp };
  return landingCache;
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

function didDocument(host: string, publicJwk: Record<string, unknown>, nextPublicJwk?: Record<string, unknown>): Record<string, unknown> {
  const did = `did:web:${host}`;
  const keys = [publicJwk, ...(nextPublicJwk && nextPublicJwk.kid !== publicJwk.kid ? [nextPublicJwk] : [])].map((k) => publicJwkOf(k) as Record<string, unknown>);
  const ids = keys.map((k) => `${did}#${k.kid ?? "jev-attest-v1"}`);
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: keys.map((k, i) => ({ id: ids[i], type: "JsonWebKey2020", controller: did, publicKeyJwk: k })),
    // A next key is published ahead of a rotation: verifiers accept it the moment it starts signing.
    assertionMethod: ids,
    authentication: ids,
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
      return json(200, discoveryDocument(deps.provider.host, deps.pricing, deps.provider.keyPair.publicJwk.kid));
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/jwks.json") {
      const current = jwksDocument(deps.provider.keyPair.publicJwk.kid, deps.provider.keyPair.publicJwk);
      const next = deps.nextPublicJwk && deps.nextPublicJwk.kid !== deps.provider.keyPair.publicJwk.kid ? [publicJwkOf(deps.nextPublicJwk)] : [];
      // Verifiers cache the keys briefly (AGENTS.md §3.12 waits 10 minutes before a key starts signing).
      const keys = json(200, { keys: [...current.keys, ...next] });
      keys.headers.set("Cache-Control", "public, max-age=300");
      return keys;
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/did.json") {
      const did = json(200, didDocument(deps.provider.host, deps.provider.keyPair.publicJwk as unknown as Record<string, unknown>, deps.nextPublicJwk));
      did.headers.set("Cache-Control", "public, max-age=300");
      return did;
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/.well-known/security.txt") {
      return new Response(SECURITY_TXT, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" } });
    }
    if ((req.method === "GET" || req.method === "HEAD") && path === "/sitemap.xml") {
      return new Response(sitemap(deps.provider.host), { status: 200, headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=86400" } });
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
        const page = landing();
        return new Response(page.html, {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": page.csp,
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            // The same URL serves the site or the discovery JSON by Accept: caches must key on it.
            Vary: "Accept",
          },
        });
      }
      const doc = json(200, discoveryDocument(deps.provider.host, deps.pricing, deps.provider.keyPair.publicJwk.kid));
      doc.headers.set("Vary", "Accept");
      return doc;
    }
    if (req.method === "GET" && path === "/favicon.ico") {
      return new Response(Uint8Array.from(atob(FAVICON_ICO_B64), (ch) => ch.charCodeAt(0)), {
        status: 200,
        headers: { "Content-Type": "image/x-icon", "Cache-Control": "public, max-age=86400" },
      });
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

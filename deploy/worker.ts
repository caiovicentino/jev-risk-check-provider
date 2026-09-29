import { handleProtected, ensureStack, doTotal, json, PROTECTED } from "./protected.js";
import { createHandler } from "../src/handler.js";
import { hashSetFromBytes, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { METAMASK_ALLOWLIST, METAMASK_FEED_META } from "../src/data/threat-feeds.js";
import { loadScamSniffer } from "./feeds.js";
import type { ExecutionContext, WorkerEnv } from "./runtime.js";
// Bundled as a Wrangler Data module (see [[rules]] in wrangler.toml).
import metamaskPhishing from "../src/data/metamask-phishing.bin";

export { RateCounter } from "./counter.js";

declare const caches: { default: { match(req: Request): Promise<Response | undefined>; put(req: Request, res: Response): Promise<void> } } | undefined;

const METAMASK = { set: hashSetFromBytes(metamaskPhishing), as_of: METAMASK_FEED_META.as_of };
const METAMASK_ALLOW = new Set(METAMASK_ALLOWLIST);

function feedsFor(env: WorkerEnv): () => Promise<ThreatIntelFeeds> {
  return async () => ({ metamaskDomains: METAMASK, metamaskAllow: METAMASK_ALLOW, ...(await loadScamSniffer(env)) });
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, PAYMENT-SIGNATURE, X-PAYMENT, X-Risk-Check-Paid, X-Risk-Check-Client",
  "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, PAYMENT-REQUIRED, X-Risk-Check-Free, X-Risk-Check-Free-Remaining, X-Payment-Error",
  "Access-Control-Max-Age": "86400",
};

const HEALTH_CACHE_KEY = "https://x402check.internal/healthz";

// Public and unauthenticated: served from the edge cache (60s) so it cannot be used
// to hammer the single quota Durable Object that every free request depends on.
async function healthz(env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
  const cache = typeof caches !== "undefined" ? caches.default : null;
  const key = new Request(HEALTH_CACHE_KEY);
  const hit = cache ? await cache.match(key) : undefined;
  if (hit) return new Response(hit.body, hit);
  const total = await doTotal(env);
  const res = json(200, total === null ? { ok: true } : { ok: true, freeEvalsToday: total }, { "Cache-Control": "public, max-age=60" });
  if (cache) {
    const put = cache.put(key, res.clone());
    if (ctx) ctx.waitUntil(put);
    else await put;
  }
  return res;
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const path = new URL(request.url).pathname;
    let res: Response;
    if (request.method === "GET" && path === "/healthz") {
      res = await healthz(env, ctx);
    } else {
      const stack = await ensureStack(env, feedsFor(env));
      if (PROTECTED.has(path)) {
        res = request.method !== "POST"
          ? json(405, { error: "method_not_allowed" })
          : await handleProtected(request, env, stack, (req) => createHandler(stack.deps)(req));
      } else {
        res = await createHandler(stack.deps)(request);
      }
    }
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.headers.set(k, v);
    return res;
  },
};

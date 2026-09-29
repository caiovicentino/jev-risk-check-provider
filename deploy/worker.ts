import { handleProtected, ensureStack, json, paymentRouting, PROTECTED } from "./protected.js";
import { createHandler } from "../src/handler.js";
import { hashSetFromBytes, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { METAMASK_ALLOWLIST, METAMASK_FEED_META } from "../src/data/threat-feeds.js";
import { FORTA_CODE_META } from "../src/data/code-feeds.js";
import { loadScamSniffer } from "./feeds.js";
import { awaitColdStart, freshFeeds, maybeRefreshFeeds, DEFAULT_FEEDS_URL } from "./fresh-feeds.js";
import { OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { sanctionsListMeta } from "../src/sanctions.js";
import { PROVIDER_VERSION } from "../src/provider.js";
import type { ExecutionContext, WorkerEnv } from "./runtime.js";
// Bundled as a Wrangler Data module (see [[rules]] in wrangler.toml).
import metamaskPhishing from "../src/data/metamask-phishing.bin";
import fortaDrainerCode from "../src/data/forta-drainer-code.bin";

const METAMASK = { set: hashSetFromBytes(metamaskPhishing), as_of: METAMASK_FEED_META.as_of };
const METAMASK_ALLOW = new Set(METAMASK_ALLOWLIST);
const FORTA_CODE = { set: hashSetFromBytes(fortaDrainerCode), as_of: FORTA_CODE_META.as_of };
const EMBEDDED = { metamaskAsOf: METAMASK_FEED_META.as_of, metamaskEntries: METAMASK_FEED_META.entries, ofacRows: OFAC_SDN_META.addresses };

function feedsFor(env: WorkerEnv): () => Promise<ThreatIntelFeeds> {
  return async () => {
    const fresh = freshFeeds().metamask; // newer verified MetaMask list, when the runtime refresh has one
    return { metamaskDomains: fresh ?? METAMASK, metamaskAllow: fresh?.allow ?? METAMASK_ALLOW, fortaCode: FORTA_CODE, ...(await loadScamSniffer(env)) };
  };
}

const ageDays = (asOf: string): number | null => {
  const t = Date.parse(asOf);
  return Number.isFinite(t) ? Math.max(0, Math.floor((Date.now() - t) / 86_400_000)) : null;
};

/** Public data-freshness report: which list versions verdicts are using right now. */
async function status(env: WorkerEnv): Promise<Response> {
  const fresh = freshFeeds();
  const ofac = sanctionsListMeta();
  let scamsniffer: Record<string, unknown> = { status: "not_configured" };
  try {
    const raw = env.RATE ? await env.RATE.get("feed:scamsniffer:meta:v1") : null;
    if (raw) {
      const m = JSON.parse(raw) as { as_of: string; domains?: number; addresses?: number; code_fingerprints?: number; commit?: string };
      scamsniffer = { as_of: m.as_of, age_days: ageDays(m.as_of), domains: m.domains, addresses: m.addresses, code_fingerprints: m.code_fingerprints, commit: m.commit, origin: "kv", note: "public data is published with a 7-day delay" };
    }
  } catch {
    scamsniffer = { status: "unavailable" };
  }
  const mm = fresh.metamask;
  // Which facilitator settles each network, and whether our price clears its published floor.
  const payments = await Promise.race([
    paymentRouting(env).catch(() => null),
    new Promise<null>((r) => setTimeout(() => r(null), 3000)),
  ]);
  return json(200, {
    version: PROVIDER_VERSION,
    time: new Date().toISOString(),
    data: {
      ofac_sdn: { as_of: ofac.publish_date, age_days: ageDays(ofac.publish_date), addresses: ofac.addresses, origin: ofac.origin, scope: "direct listing only" },
      metamask_phishing: { as_of: mm?.as_of ?? METAMASK_FEED_META.as_of, age_days: ageDays(mm?.as_of ?? METAMASK_FEED_META.as_of), entries: mm?.entries ?? METAMASK_FEED_META.entries, origin: mm ? "refreshed" : "embedded" },
      scamsniffer,
      forta_drainer_code: { as_of: FORTA_CODE_META.as_of, fingerprints: FORTA_CODE_META.fingerprints, origin: "embedded", note: "static 2023 dataset" },
    },
    refresh: { source: env.FEEDS_URL === "off" ? "off" : (env.FEEDS_URL ?? DEFAULT_FEEDS_URL), checked_at: fresh.checked_at ?? null, published_at: fresh.generated_at ?? null, error: fresh.error ?? null },
    checks: { onchain: env.ONCHAIN === "off" ? "off" : "on", simulation: env.SIMULATION === "off" ? "off" : "on", contract_verification: env.CONTRACT_INTEL === "off" ? "off" : "on" },
    payments: payments ?? { status: "unavailable" },
  }, { "Cache-Control": "public, max-age=60" });
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, PAYMENT-SIGNATURE, X-PAYMENT",
  "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, PAYMENT-REQUIRED, X-Payment-Error, Retry-After",
  "Access-Control-Max-Age": "86400",
};

// Public liveness probe; no state is touched.
function healthz(): Response {
  return json(200, { ok: true, version: PROVIDER_VERSION }, { "Cache-Control": "public, max-age=60" });
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const path = new URL(request.url).pathname;
    maybeRefreshFeeds(env, ctx, EMBEDDED);
    let res: Response;
    if (request.method === "GET" && path === "/healthz") {
      res = healthz();
    } else if (request.method === "GET" && path === "/status") {
      res = await status(env);
    } else {
      const stack = await ensureStack(env, feedsFor(env));
      if (PROTECTED.has(path)) {
        // A cold isolate briefly waits for the first verified feed refresh (newer OFAC/MetaMask).
        if (request.method === "POST") await awaitColdStart();
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

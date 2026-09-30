import { handleProtected, ensureStack, facilitatorStatus, json, paymentRouting, PROTECTED, usageFor, openApi } from "./protected.js";
import { createHandler } from "../src/handler.js";
import { hashSetFromBytes, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { METAMASK_ALLOWLIST, METAMASK_FEED_META } from "../src/data/threat-feeds.js";
import { FORTA_CODE_META } from "../src/data/code-feeds.js";
import { loadScamSniffer } from "./feeds.js";
import { awaitColdStart, freshFeeds, maybeRefreshFeeds, DEFAULT_FEEDS_URL } from "./fresh-feeds.js";
import { OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { sanctionsListMeta } from "../src/sanctions.js";
import { PROVIDER_VERSION } from "../src/provider.js";
import { KW, runKitWatch, type KitWatchStats } from "./kit-watch.js";
import { CREDIT_PRICING, handleCredits } from "./credits.js";
import type { ExecutionContext, ScheduledController, WorkerEnv } from "./runtime.js";
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
  // The provider's own watch: coverage (cursor vs head, gaps) and what it has flagged.
  let kitWatch: Record<string, unknown> = { status: env.KIT_WATCH === "off" ? "off" : "not_configured" };
  try {
    const raw = env.KIT_WATCH !== "off" && env.RATE ? await env.RATE.get(KW.stats) : null;
    if (raw) {
      const st = JSON.parse(raw) as KitWatchStats;
      kitWatch = {
        updated_at: st.updated_at,
        chains: Object.fromEntries(
          Object.entries(st.chains).map(([chain, c]) => [chain, { lag_blocks: Math.max(0, c.head - c.cursor), scanned_blocks: c.scanned_blocks, flagged: c.flagged, delegates_classified: c.delegates, gaps: c.gaps.length, ...(c.error ? { error: c.error } : {}) }]),
        ),
        note: "EIP-7702 delegations to poisoners and sweepers, and new drainer-kit deployments, observed block by block; the list itself is private",
      };
    }
  } catch {
    kitWatch = { status: "unavailable" };
  }
  // Which facilitator settles each network, and whether our price clears its published floor;
  // and whether each configured facilitator answers (an authenticated one's key stays private).
  const within = <T>(p: Promise<T>): Promise<T | null> => Promise.race([p.catch(() => null), new Promise<null>((r) => setTimeout(() => r(null), 3000))]);
  const [payments, facilitators] = await Promise.all([within(paymentRouting(env)), within(facilitatorStatus(env))]);
  return json(200, {
    version: PROVIDER_VERSION,
    time: new Date().toISOString(),
    data: {
      ofac_sdn: { as_of: ofac.publish_date, age_days: ageDays(ofac.publish_date), addresses: ofac.addresses, origin: ofac.origin, scope: "direct listing only" },
      metamask_phishing: { as_of: mm?.as_of ?? METAMASK_FEED_META.as_of, age_days: ageDays(mm?.as_of ?? METAMASK_FEED_META.as_of), entries: mm?.entries ?? METAMASK_FEED_META.entries, origin: mm ? "refreshed" : "embedded" },
      scamsniffer,
      forta_drainer_code: { as_of: FORTA_CODE_META.as_of, fingerprints: FORTA_CODE_META.fingerprints, origin: "embedded", note: "static 2023 dataset" },
      kit_watch: kitWatch,
    },
    refresh: { source: env.FEEDS_URL === "off" ? "off" : (env.FEEDS_URL ?? DEFAULT_FEEDS_URL), checked_at: fresh.checked_at ?? null, published_at: fresh.generated_at ?? null, error: fresh.error ?? null },
    checks: { onchain: env.ONCHAIN === "off" ? "off" : "on", simulation: env.SIMULATION === "off" ? "off" : "on", contract_verification: env.CONTRACT_INTEL === "off" ? "off" : "on" },
    payments: payments ?? { status: "unavailable" },
    facilitators: facilitators ?? { status: "unavailable" },
    credits: env.CREDITS ? { status: "on", ...CREDIT_PRICING } : { status: "off" },
  }, { "Cache-Control": "public, max-age=60" });
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, PAYMENT-SIGNATURE, X-PAYMENT",
  "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, PAYMENT-REQUIRED, X-Payment-Error, Retry-After, X-Credits-Balance, X-Credits-Charged",
  "Access-Control-Max-Age": "86400",
};

// Public liveness probe; no state is touched.
function healthz(): Response {
  return json(200, { ok: true, version: PROVIDER_VERSION }, { "Cache-Control": "public, max-age=60" });
}

export default {
  async fetch(incoming: Request, env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
    if (incoming.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    // HEAD is GET without a body (RFC 9110): discovery tools check /favicon.ico and pages with HEAD.
    const head = incoming.method === "HEAD";
    const request = head ? new Request(incoming.url, { method: "GET", headers: incoming.headers }) : incoming;
    const path = new URL(request.url).pathname;
    maybeRefreshFeeds(env, ctx, EMBEDDED);
    let res: Response;
    if (request.method === "GET" && path === "/healthz") {
      res = healthz();
    } else if (request.method === "GET" && path === "/status") {
      res = await status(env);
    } else if (request.method === "GET" && path === "/openapi.json") {
      res = json(200, openApi(env), { "Cache-Control": "public, max-age=300" });
    } else {
      const stack = await ensureStack(env, feedsFor(env));
      if (path === "/v1/credits") {
        res = await handleCredits(request, env, stack);
      } else if (PROTECTED.has(path)) {
        // A cold isolate briefly waits for the first verified feed refresh (newer OFAC/MetaMask).
        if (request.method === "POST") await awaitColdStart();
        res = request.method !== "POST"
          ? json(405, usageFor(path), { Allow: "POST" })
          : await handleProtected(request, env, stack, (req) => createHandler(stack.deps)(req));
      } else {
        res = await createHandler(stack.deps)(request);
      }
    }
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.headers.set(k, v);
    return head ? new Response(null, { status: res.status, headers: res.headers }) : res;
  },

  // Kit watch cron (wrangler.toml [triggers]): scans new Ethereum and Base blocks.
  async scheduled(_controller: ScheduledController, env: WorkerEnv, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runKitWatch(env).catch(() => null));
  },
};

// Durable Object classes must be exported by the main module (wrangler.toml [[durable_objects.bindings]]).
export { CreditLedger } from "./credits.js";

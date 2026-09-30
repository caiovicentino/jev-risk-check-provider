import { handleProtected, ensureDeps, ensureStack, facilitatorStatus, isProductionHost, jevFor, json, paymentRouting, PROTECTED, usageFor, openApi } from "./protected.js";
import { maybeRunModelCanary, MODEL_CANARY_KEY } from "./model-canary.js";
import { maybeRefreshScamSniffer } from "./scamsniffer-refresh.js";
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

/** Seconds after which /status reports the kit watch as stale (the cron runs every minute). */
const KIT_WATCH_STALE_S = 180;
import { CREDIT_PRICING, handleCredits, retryPendingCredits } from "./credits.js";
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
      const m = JSON.parse(raw) as { as_of: string; code_as_of?: string; refreshed_at?: string; domains?: number; addresses?: number; code_fingerprints?: number; commit?: string };
      // Stale when our last refresh (not the list's own date) is more than 3 days old.
      const refreshedDays = ageDays(m.refreshed_at ?? m.as_of);
      scamsniffer = {
        as_of: m.as_of,
        age_days: ageDays(m.as_of),
        refreshed_at: m.refreshed_at ?? null,
        stale: typeof refreshedDays === "number" ? refreshedDays > 3 : true,
        domains: m.domains,
        addresses: m.addresses,
        code_fingerprints: m.code_fingerprints,
        ...(m.code_as_of ? { code_as_of: m.code_as_of } : {}),
        commit: m.commit,
        origin: "kv",
        note: "public data is published with a 7-day delay",
      };
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
      // The cron runs every minute: stats older than 3 minutes mean the watch has stalled,
      // whatever lag they last recorded.
      const age = Math.max(0, Math.round((Date.now() - Date.parse(st.updated_at)) / 1000));
      const stale = !Number.isFinite(age) || age > KIT_WATCH_STALE_S;
      kitWatch = {
        status: stale ? "stale" : "ok",
        updated_at: st.updated_at,
        age_s: Number.isFinite(age) ? age : null,
        chains: Object.fromEntries(
          Object.entries(st.chains).map(([chain, c]) => [
            chain,
            {
              lag_blocks: Math.max(0, c.head - c.cursor),
              scanned_blocks: c.scanned_blocks,
              flagged: c.flagged,
              delegates_classified: c.delegates,
              gaps: c.gaps.length,
              ...(c.degraded ? { degraded_reads: c.degraded } : {}),
              ...(c.dropped ? { dropped_entries: c.dropped } : {}),
              ...(c.error ? { error: c.error } : {}),
            },
          ]),
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
    attestation: attestationStatus(env),
    model: await modelStatus(env),
    ...(env.ENABLE_TESTNETS === "true" ? { testnets: isProductionHost(env) ? "requested but ignored on a production host" : "on" } : {}),
  }, { "Cache-Control": "public, max-age=60" });
}

/** The last model canary: whether fixed cases still land where they must, and which revision answered. */
async function modelStatus(env: WorkerEnv): Promise<Record<string, unknown>> {
  if (!env.AI_GATEWAY_API_KEY && !env.TYPESAFE_API_KEY) return { status: "not_configured" };
  try {
    const raw = env.RATE ? await env.RATE.get(MODEL_CANARY_KEY) : null;
    if (!raw) return { alias: env.TYPESAFE_API_KEY ? "jev-latest" : "typesafe-ai/jev", canary: null };
    const report = JSON.parse(raw) as { at: string; ok: boolean; model_id: string | null; cases: unknown[] };
    const ageH = Math.round((Date.now() - Date.parse(report.at)) / 36e5);
    return { alias: env.TYPESAFE_API_KEY ? "jev-latest" : "typesafe-ai/jev", model_id: report.model_id, canary: { at: report.at, age_hours: ageH, ok: report.ok, stale: ageH > 36, cases: report.cases } };
  } catch {
    return { status: "unavailable" };
  }
}

/** The attestation key's health, public data only: its kid, its RFC 7638 thumbprint, and the self-check. */
function attestationStatus(env: WorkerEnv): Record<string, unknown> {
  try {
    const { keyStatus } = ensureDeps(env, feedsFor(env));
    return { ok: keyStatus.ok, kid: keyStatus.kid, thumbprint: keyStatus.thumbprint, ...(keyStatus.reason ? { reason: keyStatus.reason } : {}) };
  } catch {
    return { ok: false, reason: "the key could not be checked" };
  }
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, PAYMENT-SIGNATURE, X-PAYMENT",
  "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, PAYMENT-REQUIRED, X-Payment-Error, Retry-After, X-Credits-Balance, X-Credits-Charged",
  "Access-Control-Max-Age": "86400",
};

// Public liveness probe; no state is touched.
function healthz(env: WorkerEnv): Response {
  const attestation = attestationStatus(env);
  // 503 while the key cannot sign verifiable attestations: paid routes refuse all work then.
  return json(
    attestation.ok === true ? 200 : 503,
    { ok: attestation.ok === true, version: PROVIDER_VERSION, commit: env.GIT_COMMIT ?? null, attestation_key: attestation.ok === true ? "ok" : "misconfigured" },
    { "Cache-Control": "public, max-age=60" },
  );
}

/** Headers every response carries: no MIME sniffing, no referrer leakage, HTTPS pinned on the production host. */
function securityHeaders(env: WorkerEnv, local: boolean): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    ...(local || !isProductionHost(env) ? {} : { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" }),
  };
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The request router; `fetch` wraps it, so that nothing escapes as an HTML error page. */
async function handle(incoming: Request, env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
  const url = new URL(incoming.url);
  // Local development: a local host, or a loopback client (wrangler dev rewrites the URL to the
  // route's host over http). Cloudflare sets CF-Connecting-IP itself, so a remote client cannot claim loopback.
  const client = incoming.headers.get("CF-Connecting-IP") ?? "";
  const local = LOCAL_HOSTS.has(url.hostname) || client === "127.0.0.1" || client === "::1";
  // HTTPS only: a page redirects; an API call is refused before its body or a bearer token is read.
  if (url.protocol === "http:" && !local) {
    if (incoming.method === "GET" || incoming.method === "HEAD") return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}${url.search}` } });
    return json(403, { error: "https_required", detail: "use https://; nothing sent over plain HTTP is processed" });
  }
  if (incoming.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  // HEAD is GET without a body (RFC 9110): discovery tools check /favicon.ico and pages with HEAD.
  const head = incoming.method === "HEAD";
  const request = head ? new Request(incoming.url, { method: "GET", headers: incoming.headers }) : incoming;
  const path = url.pathname;
  maybeRefreshFeeds(env, ctx, EMBEDDED);
  // Unpaid, unauthenticated traffic to paid routes and /status is rate-limited per IP (it costs work).
  const paidRoute = PROTECTED.has(path) || path === "/v1/credits";
  const unpaid = !request.headers.get("PAYMENT-SIGNATURE") && !request.headers.get("authorization");
  if (env.UNPAID_LIMITER && ((paidRoute && request.method === "POST" && unpaid) || path === "/status")) {
    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const { success } = await env.UNPAID_LIMITER.limit({ key: `${path === "/status" ? "status" : "unpaid"}:${ip}` }).catch(() => ({ success: true }));
    if (!success) return json(429, { error: "rate_limited", detail: "too many unpaid requests; pay or retry in a minute" }, { "Retry-After": "60", ...CORS_HEADERS });
  }
  let res: Response;
  if (request.method === "GET" && path === "/healthz") {
    res = healthz(env);
  } else if (request.method === "GET" && path === "/status") {
    res = await status(env);
  } else if (request.method === "GET" && path === "/openapi.json") {
    res = json(200, openApi(env), { "Cache-Control": "public, max-age=300" });
  } else if (!paidRoute) {
    // Identity documents, the site and discovery never wait for the payment stack (a hung facilitator).
    res = await createHandler(ensureDeps(env, feedsFor(env)).deps)(request);
  } else {
    const stack = await ensureStack(env, feedsFor(env));
    if (path === "/v1/credits") {
      res = await handleCredits(request, env, stack);
    } else {
      // A cold isolate briefly waits for the first verified feed refresh (newer OFAC/MetaMask).
      if (request.method === "POST") await awaitColdStart();
      res = request.method !== "POST"
        ? json(405, usageFor(path), { Allow: "POST" })
        : await handleProtected(request, env, stack, (req) => createHandler(stack.deps)(req), ctx);
    }
  }
  for (const [k, v] of Object.entries({ ...CORS_HEADERS, ...securityHeaders(env, local) })) res.headers.set(k, v);
  return head ? new Response(null, { status: res.status, headers: res.headers }) : res;
}

export default {
  async fetch(incoming: Request, env: WorkerEnv, ctx?: ExecutionContext): Promise<Response> {
    try {
      return await handle(incoming, env, ctx);
    } catch (err) {
      // Never an HTML error page or a stack trace: a JSON 500, logged without request data.
      console.error(`unhandled: ${String(err).slice(0, 300)}`);
      return new Response(JSON.stringify({ error: "internal_error" }), { status: 500, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS_HEADERS } });
    }
  },

  // Kit watch cron (wrangler.toml [triggers]): scans new Ethereum and Base blocks.
  async scheduled(controller: ScheduledController, env: WorkerEnv, ctx: ExecutionContext): Promise<void> {
    // Twice a day: the ScamSniffer domain and address sets, rebuilt into KV (GPL: runtime only).
    ctx.waitUntil(
      maybeRefreshScamSniffer(env, controller.scheduledTime).catch((err: unknown) => {
        console.error(`scamsniffer refresh failed: ${String(err).slice(0, 200)}`);
      }),
    );
    // Twice a day: fixed cases through the live model (drift in the revision behind the alias).
    ctx.waitUntil(
      maybeRunModelCanary(env, jevFor(env), controller.scheduledTime).catch((err: unknown) => {
        console.error(`model canary run failed: ${String(err).slice(0, 200)}`);
      }),
    );
    ctx.waitUntil(
      runKitWatch(env).catch((err: unknown) => {
        console.error(`kit watch run failed: ${String(err).slice(0, 300)}`);
        return null;
      }),
    );
    // Credits for packs whose payment settled but whose ledger write failed.
    ctx.waitUntil(
      retryPendingCredits(env).catch((err: unknown) => {
        console.error(`queued credits retry failed: ${String(err).slice(0, 200)}`);
        return 0;
      }),
    );
  },
};

// Durable Object classes must be exported by the main module (wrangler.toml [[durable_objects.bindings]]).
export { CreditLedger } from "./credits.js";
export { PaymentClaim } from "./payment-claims.js";

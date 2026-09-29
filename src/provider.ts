import { inputHash, signJws, type AttestationChecks, type JwsClaims, type KeyPair } from "./jws.js";
import { buildQuestions, buildState, deriveChecks, QUESTION_SET_VERSION, type JevAnswers, type JevLike, type JevQuestions, type Usage } from "./jev.js";
import { categoriesFor, computeScore, extractInputs } from "./scoring.js";
import { SANCTIONS_LIST_META } from "./sanctions.js";
import { DEFAULT_RPC, type OnchainEvidence, type OnchainLookup } from "./onchain.js";
import { checkFeeds, isAllowlistedDomain, type FeedResult, type ThreatIntelFeeds } from "./threat-intel.js";
import { GRANTING_INTERACTIONS, type Answer, type Evidence, type RiskCheckDiscovery, type RiskCheckRequest, type RiskCheckResult, type RiskTier } from "./types.js";

export const PROVIDER_DID_PREFIX = "did:web:";
export const ATTESTATION_TTL_MS = 60 * 60 * 1000;
export const PROVIDER_VERSION = "0.2.0";

export type ProviderConfig = {
  host: string;
  keyPair: KeyPair;
  jev: JevLike | null;
  /** Provider-side on-chain facts; null/undefined disables lookups (e.g. synthetic corpora). */
  onchain?: OnchainLookup | null | undefined;
  /** Community threat feeds (phishing domains, scam addresses); undefined = none consulted. */
  feeds?: (() => Promise<ThreatIntelFeeds> | ThreatIntelFeeds) | undefined;
};

// Deterministic caps for curated-feed hits (independent of model sampling).
export const FEED_CAPS: Record<string, number> = {
  "metamask-phishing-detect": 20,
  "scamsniffer-addresses": 20,
  "scamsniffer-domains": 40,
};

// Approvals/permits normally go to contracts (routers, protocols, marketplaces);
// granting an EOA control over assets is a classic drainer pattern.
export const APPROVAL_TO_EOA_CAP = 55;
export const APPROVAL_TO_FRESH_EOA_CAP = 40;

export type ScoredEvaluation = {
  result: RiskCheckResult;
  answers: JevAnswers | null;
  latencyMs: number;
  usage: Usage | null;
  error: string | null;
};

export type PricingInfo = { unitUsd: string; networks: string[] };

export function discoveryDocument(host: string, pricing?: PricingInfo): RiskCheckDiscovery {
  return {
    name: "x402check",
    version: PROVIDER_VERSION,
    description:
      "Pre-payment risk checks for x402 agent commerce and wallets: deterministic OFAC SDN address screening and domain-impersonation analysis, provider-observed on-chain facts, and a Jev typed-model evaluation of the operation content for injected or manipulated intent. Every verdict is an ES256 attestation that states which checks the provider actually ran.",
    endpoint: "/v1/risk-check",
    batch_endpoint: "/v1/risk-check/batch",
    method: "POST",
    ...(pricing
      ? { pricing: { amount: pricing.unitUsd, currency: "USDC", protocol: "x402", network: pricing.networks[0] ?? "", unit: "per evaluation; batch billed per item", networks: pricing.networks } }
      : {}),
    signals: ["ofac_sdn_address", "domain_impersonation", "onchain_activity", "operation_context_intent"],
    chains_supported: Object.keys(DEFAULT_RPC),
    response_time_ms: "<3000",
    attestation: {
      jwks_url: `${schemeForHost(host)}://${host}/.well-known/jwks.json`,
      algorithm: "ES256",
      kid: "jev-attest-v1",
      ttl: "1h",
      issuer: `${PROVIDER_DID_PREFIX}${host}`,
      claims: ["iss", "sub", "score", "tier", "iat", "exp", "jti", "categories", "input_hash", "checks", "asserted", "aud", "payment"],
    },
    data_sources: {
      ofac_sdn: `${SANCTIONS_LIST_META.source} (published ${SANCTIONS_LIST_META.publish_date}, ${SANCTIONS_LIST_META.addresses} digital currency addresses; direct listing only)`,
      onchain: "public JSON-RPC: EVM eth_getCode/eth_getTransactionCount/eth_getBalance; Solana getAccountInfo/getSignaturesForAddress",
      model: `TypeSafe Jev System One, question set ${QUESTION_SET_VERSION}`,
    },
  };
}

export function schemeForHost(host: string): string {
  return host.startsWith("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
}

function isUnit(v: unknown): boolean {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;
}

// Scoring treats a missing answer as "no risk" (noul→0, trust→2), so a partial or
// malformed model response would otherwise yield a signed low-risk attestation.
// Require every question to be answered with the expected, in-range type.
export function answersComplete(answers: unknown, questions: JevQuestions): answers is JevAnswers {
  if (!answers || typeof answers !== "object") return false;
  const a = answers as Record<string, Answer | undefined>;
  for (const [id, q] of Object.entries(questions)) {
    const ans = a[id];
    if (!ans || ans.type !== q.type) return false;
    if (ans.type === "noul" && !isUnit(ans.noul)) return false;
    if (ans.type === "choice") {
      const allowed = q.criteria && !Array.isArray(q.criteria) ? Object.keys(q.criteria) : [];
      if (typeof ans.choice !== "string" || !allowed.includes(ans.choice) || !ans.probabilities || typeof ans.probabilities !== "object") return false;
    }
    if (ans.type === "score" && !(typeof ans.score === "number" && Number.isFinite(ans.score) && ans.score >= 0 && ans.score <= 4)) return false;
  }
  return true;
}

type Verdict = { score: number; tier: RiskTier; categories: string[]; model: string };

export class Provider {
  constructor(private readonly config: ProviderConfig) {}

  get host(): string {
    return this.config.host;
  }

  get jwksUrl(): string {
    return `${schemeForHost(this.config.host)}://${this.config.host}/.well-known/jwks.json`;
  }

  get keyPair(): KeyPair {
    return this.config.keyPair;
  }

  async evaluate(req: RiskCheckRequest): Promise<ScoredEvaluation> {
    const started = Date.now();
    const fail = (error: string, usage: Usage | null = null): ScoredEvaluation => ({
      result: { checked: false },
      answers: null,
      latencyMs: Date.now() - started,
      usage,
      error,
    });

    const checks = deriveChecks(req);
    if (!checks.subject || !checks.sanctions) return fail("invalid_subject");
    const network = checks.subject.caip2 ?? req.chain;
    const onchainP: Promise<OnchainEvidence> = this.config.onchain
      ? this.config.onchain(checks.subject, network).catch(() => ({ status: "unavailable" as const, ...(network ? { network } : {}) }))
      : Promise.resolve({ status: "unsupported" as const, ...(network ? { network } : {}) });

    let feedResults: FeedResult[] = [];
    try {
      const feeds = this.config.feeds ? await this.config.feeds() : {};
      feedResults = checkFeeds(feeds, checks.subject, checks.domain).results;
      // A curated allowlist (MetaMask's) overrides our heuristic look-alike analysis.
      if (checks.domain && checks.domain.impersonation !== "none" && isAllowlistedDomain(feeds, checks.domain)) {
        checks.domain = { ...checks.domain, impersonation: "none", signals: [...checks.domain.signals, "feed_allowlisted"] };
      }
    } catch {
      feedResults = [];
    }

    // A directly listed address is a deterministic verdict: no model call, no sampling.
    if (checks.sanctions.status === "listed") {
      const onchain = await onchainP;
      const verdict: Verdict = { score: 0, tier: "critical", categories: ["sanctioned_address", "compliance_risk"], model: "skipped" };
      return this.attest(req, checks, onchain, feedResults, verdict, [], null, null, started);
    }

    const jev = this.config.jev;
    if (!jev) return fail("jev_unconfigured");

    const questions = buildQuestions();
    let answers: JevAnswers;
    let usage: Usage;
    let onchain: OnchainEvidence;
    try {
      const [call, facts] = await Promise.all([jev.systemOne(buildState(req, checks, feedResults), questions), onchainP]);
      answers = call.answers;
      usage = call.usage;
      onchain = facts;
    } catch (err) {
      return fail(String(err));
    }
    if (!answersComplete(answers, questions)) return fail("jev_malformed_answers", usage);

    const inputs = extractInputs(req, answers as Record<string, Answer>);
    const callerFlagged = req.screening?.sanctions === "flagged";
    const impersonation = checks.domain?.impersonation ?? "none";
    const hits = feedResults.filter((f) => f.status === "hit");
    // ScamSniffer's domain list also contains popular shared hosts (URL shorteners,
    // storage platforms): its hit caps the score only when our own domain analysis
    // corroborates it; otherwise it is surfaced to the model and the evidence only.
    const corroborated = !!checks.domain && (checks.domain.impersonation !== "none" || checks.domain.signals.some((s) => s === "suspicious_tld" || s === "lure_keyword" || s === "punycode"));
    const caps = hits
      .filter((h) => h.source !== "scamsniffer-domains" || corroborated)
      .map((h) => FEED_CAPS[h.source])
      .filter((c): c is number => c !== undefined);
    const approvalToEoa =
      req.interaction !== undefined && GRANTING_INTERACTIONS.has(req.interaction.type) && onchain.status === "ok" && onchain.is_contract === false;
    if (approvalToEoa) caps.push(onchain.activity === "none" ? APPROVAL_TO_FRESH_EOA_CAP : APPROVAL_TO_EOA_CAP);
    const breakdown = computeScore(inputs, undefined, {
      callerFlagged,
      impersonation,
      ...(caps.length ? { evidenceCap: Math.min(...caps) } : {}),
    });
    const verdict: Verdict = {
      score: breakdown.score,
      tier: breakdown.tier,
      categories: categoriesFor(inputs, {
        callerFlagged,
        impersonation,
        newAddress: onchain.activity === "none",
        phishingDomain: hits.some((h) => h.source === "metamask-phishing-detect" || (h.source === "scamsniffer-domains" && corroborated)),
        communityFlaggedDomain: hits.some((h) => h.source === "scamsniffer-domains" && !corroborated),
        knownScamAddress: hits.some((h) => h.kind === "address"),
        approvalToEoa,
      }),
      model: QUESTION_SET_VERSION,
    };
    return this.attest(req, checks, onchain, feedResults, verdict, Object.keys(questions), answers, usage, started);
  }

  private attest(
    req: RiskCheckRequest,
    checks: ReturnType<typeof deriveChecks>,
    onchain: OnchainEvidence,
    feeds: FeedResult[],
    verdict: Verdict,
    questionIds: string[],
    answers: JevAnswers | null,
    usage: Usage | null,
    started: number,
  ): ScoredEvaluation {
    const sanctions = checks.sanctions as NonNullable<typeof checks.sanctions>;
    const now = Date.now();
    const payment = req.payment
      ? (Object.fromEntries(Object.entries(req.payment).filter(([, v]) => typeof v === "string")) as Record<string, string>)
      : undefined;
    const hash = inputHash({
      version: QUESTION_SET_VERSION,
      wallet: req.wallet,
      chain: req.chain ?? null,
      domain: req.domain ?? null,
      context: req.context ?? null,
      aud: req.aud ?? null,
      screening: req.screening?.sanctions ?? null,
      authorization: req.authorization ? { pre_authorized: req.authorization.pre_authorized, source: req.authorization.source ?? null } : null,
      payment: payment ?? null,
      interaction: req.interaction ? { type: req.interaction.type, unlimited: req.interaction.unlimited ?? null } : null,
      sanctions_list: `${sanctions.list}@${sanctions.as_of}`,
      feeds: feeds.map((f) => `${f.source}@${f.as_of}`),
      questions: questionIds,
    });
    const domain = checks.domain
      ? {
          host: checks.domain.host,
          registrable: checks.domain.registrable,
          official: checks.domain.official,
          impersonation: checks.domain.impersonation,
          ...(checks.domain.brand ? { brand: checks.domain.brand } : {}),
          signals: checks.domain.signals,
        }
      : undefined;
    const evidence: Evidence = { sanctions, ...(domain ? { domain } : {}), onchain, ...(feeds.length ? { feeds } : {}), model: verdict.model };
    const signedChecks: AttestationChecks = {
      sanctions: { list: sanctions.list, as_of: sanctions.as_of, status: sanctions.status },
      ...(domain ? { domain: { host: domain.host, impersonation: domain.impersonation } } : {}),
      onchain: { status: onchain.status, ...(onchain.network ? { network: onchain.network } : {}), ...(onchain.activity ? { activity: onchain.activity } : {}) },
      ...(feeds.length ? { feeds: feeds.map((f) => `${f.source}@${f.as_of || "n/a"}:${f.status}`) } : {}),
      model: verdict.model,
    };
    // Caller-supplied screening/authorization are self-reported: surface them so a
    // relying party can tell them apart from what the provider verified (`checks`).
    const asserted = {
      ...(req.screening ? { screening: req.screening.sanctions } : {}),
      ...(req.authorization ? { pre_authorized: req.authorization.pre_authorized } : {}),
    };
    const claims: JwsClaims = {
      iss: `${PROVIDER_DID_PREFIX}${this.config.host}`,
      sub: req.wallet,
      score: verdict.score,
      tier: verdict.tier,
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + ATTESTATION_TTL_MS) / 1000),
      jti: crypto.randomUUID(),
      categories: verdict.categories,
      input_hash: hash,
      checks: signedChecks,
      ...(Object.keys(asserted).length ? { asserted } : {}),
      ...(req.aud ? { aud: req.aud } : {}),
      ...(payment && Object.keys(payment).length ? { payment } : {}),
      ...(req.interaction ? { interaction: req.interaction.type } : {}),
    };
    const jws = signJws(claims, this.config.keyPair.publicJwk.kid, this.config.keyPair.privatePem);
    return {
      result: {
        checked: true,
        score: verdict.score,
        tier: verdict.tier,
        provider: claims.iss,
        categories: verdict.categories,
        jws,
        jwks_url: this.jwksUrl,
        checked_at: new Date(now).toISOString(),
        expires_at: new Date(now + ATTESTATION_TTL_MS).toISOString(),
        evidence,
      },
      answers,
      latencyMs: Date.now() - started,
      usage,
      error: null,
    };
  }
}

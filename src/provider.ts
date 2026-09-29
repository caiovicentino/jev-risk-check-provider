import { inputHash, signJws, type AttestationChecks, type JwsClaims, type KeyPair } from "./jws.js";
import { buildQuestions, buildState, deriveChecks, QUESTION_SET_VERSION, type JevAnswers, type JevLike, type JevQuestions, type Usage } from "./jev.js";
import { categoriesFor, computeScore, extractInputs } from "./scoring.js";
import { sanctionsListMeta } from "./sanctions.js";
import { DEFAULT_RPC, type OnchainEvidence, type OnchainLookup } from "./onchain.js";
import { checkFeeds, codeFeedResults, hasCodeFeeds, isAllowlistedDomain, matchCode, type FeedResult, type ThreatIntelFeeds } from "./threat-intel.js";
import type { Declared, SimulationEvidence, Simulator } from "./simulation.js";
import { parseSubject, type Subject } from "./address.js";
import type { ContractIntel } from "./contract-intel.js";
import { fingerprintsOf } from "./code-fingerprint.js";
import { createHash } from "node:crypto";
import { GRANTING_INTERACTIONS, type Answer, type Evidence, type RiskCheckDiscovery, type RiskCheckRequest, type RiskCheckResult, type RiskTier } from "./types.js";

export const PROVIDER_DID_PREFIX = "did:web:";
export const ATTESTATION_TTL_MS = 60 * 60 * 1000;
export const PROVIDER_VERSION = "0.3.2";

export type ProviderConfig = {
  host: string;
  keyPair: KeyPair;
  jev: JevLike | null;
  /** Provider-side on-chain facts; null/undefined disables lookups (e.g. synthetic corpora). */
  onchain?: OnchainLookup | null | undefined;
  /** Community threat feeds (phishing domains, scam addresses); undefined = none consulted. */
  feeds?: (() => Promise<ThreatIntelFeeds> | ThreatIntelFeeds) | undefined;
  /** EVM transaction simulation (eth_simulateV1); null/undefined disables it. */
  simulator?: Simulator | null | undefined;
  /** Contract source-verification lookups (block explorers); null/undefined disables them. */
  contractIntel?: ContractIntel | null | undefined;
};

// Transaction simulation and contract reputation caps.
export const HIDDEN_RECIPIENT_CAP = 40;
/** Logic code byte-identical (up to compiler metadata) to a listed drainer contract's. */
export const DRAINER_CODE_CAP = 30;
/** Undisclosed recipient reached through a source-verified contract: review. */
export const VERIFIED_FORWARDER_CAP = 75;
/** Recipients or spenders that could not be classified, or truncated logs: review. */
export const INCOMPLETE_SIMULATION_CAP = 75;
export const UNVERIFIED_SINK_CAP = 55;
export const UNVERIFIED_SPENDER_CAP = 75;

const FAIL_REASONS: Record<string, string> = {
  invalid_subject: "invalid_subject",
  jev_unconfigured: "model_unconfigured",
  jev_malformed_answers: "model_malformed_answers",
};

// Deterministic caps for curated-feed hits (independent of model sampling).
export const FEED_CAPS: Record<string, number> = {
  "metamask-phishing-detect": 20,
  "scamsniffer-addresses": 20,
  "scamsniffer-domains": 40,
  "forta-phishing-code": DRAINER_CODE_CAP,
  "scamsniffer-code": DRAINER_CODE_CAP,
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

export type PricingInfo = { unitUsd: string; simulationUsd?: string; networks: string[] };

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
      ? {
          pricing: {
            amount: pricing.unitUsd,
            currency: "USDC",
            protocol: "x402",
            network: pricing.networks[0] ?? "",
            unit: pricing.simulationUsd
              ? `per evaluation ($0.002 on Solana); $${pricing.simulationUsd} when the request includes a transaction that is simulated; batch billed per item`
              : "per evaluation ($0.002 on Solana); batch billed per item",
            ...(pricing.simulationUsd ? { amount_with_transaction: pricing.simulationUsd } : {}),
            networks: pricing.networks,
          },
        }
      : {}),
    signals: ["ofac_sdn_address", "threat_feeds", "domain_impersonation", "onchain_activity", "transaction_simulation", "contract_verification", "drainer_code_fingerprint", "operation_context_intent"],
    chains_supported: Object.keys(DEFAULT_RPC),
    response_time_ms: "<3000",
    attestation: {
      jwks_url: `${schemeForHost(host)}://${host}/.well-known/jwks.json`,
      algorithm: "ES256",
      kid: "jev-attest-v1",
      ttl: "1h",
      issuer: `${PROVIDER_DID_PREFIX}${host}`,
      claims: ["iss", "sub", "score", "tier", "iat", "exp", "jti", "categories", "input_hash", "request_hash", "checks", "asserted", "aud", "payment", "interaction"],
    },
    data_sources: {
      ofac_sdn: `${sanctionsListMeta().source} (published ${sanctionsListMeta().publish_date}, ${sanctionsListMeta().addresses} digital currency addresses; direct listing only)`,
      onchain: "public JSON-RPC: EVM eth_getCode/eth_getTransactionCount/eth_getBalance; Solana getAccountInfo/getSignaturesForAddress",
      simulation: "eth_simulateV1 with traceTransfers on public RPCs with fallbacks (Ethereum, Base, Polygon, Arbitrum, Optimism, BSC)",
      contract_verification: "Blockscout API v2 (source verification status)",
      drainer_code_fingerprints: "sha256 of metadata-stripped logic code of contracts listed by Forta labelled-datasets (MIT) and ScamSniffer; token, NFT, proxy and tiny code is never fingerprinted",
      model: `TypeSafe Jev System One, question set ${QUESTION_SET_VERSION}`,
    },
  };
}

/**
 * What the caller names for simulation purposes: the payee, scoped to the payment's
 * asset and amount when those are machine-checkable, and the subject for any asset
 * (unless the subject is the payee, whose scope the payment defines). Only the payee
 * counts as intended to keep assets; a named contract subject is still checked as a
 * sink. Addresses are canonical, so CAIP-10 and checksummed forms name the same wallet.
 */
export function declaredScope(req: RiskCheckRequest, subject: Subject): Declared[] {
  const canonical = (a: string) => parseSubject(a)?.canonical ?? a.toLowerCase();
  const out: Declared[] = [];
  const payTo = req.payment?.pay_to ? canonical(req.payment.pay_to) : undefined;
  if (payTo) {
    // A symbol ("USDC") cannot be matched to a token contract: then neither asset nor amount scopes it.
    const asset = req.payment?.asset;
    const scoped = asset !== undefined && (asset === "native" || /^0x[0-9a-fA-F]{40}$/.test(asset));
    out.push({ address: payTo, payee: true, ...(scoped ? { asset: asset.toLowerCase(), ...(req.payment?.amount ? { max: req.payment.amount } : {}) } : {}) });
  }
  if (subject.format === "evm" && subject.canonical !== payTo) out.push({ address: subject.canonical });
  return out;
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
      // A stable public reason code; the raw error (which may carry upstream details) stays internal.
      result: { checked: false, reason: FAIL_REASONS[error] ?? "model_unavailable" },
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
    let feeds: ThreatIntelFeeds = {};
    try {
      feeds = this.config.feeds ? await this.config.feeds() : {};
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

    const granting = req.interaction !== undefined && GRANTING_INTERACTIONS.has(req.interaction.type);
    const simulationP: Promise<SimulationEvidence | undefined> =
      req.transaction && this.config.simulator
        ? this.config.simulator(req.transaction, network, {
            declared: declaredScope(req, checks.subject),
            ...(hasCodeFeeds(feeds) ? { codeMatch: (fp: string) => matchCode(feeds, fp) } : {}),
          }).catch(() => ({ status: "unavailable" as const, ...(network ? { network } : {}) }))
        : Promise.resolve(undefined);
    // Started early: the subject's verification status only matters when the user
    // grants it control over assets, and the lookup is the slowest external call.
    const subjectIntelP =
      granting && this.config.contractIntel && checks.subject.format === "evm"
        ? this.config.contractIntel(checks.subject.canonical, network).catch(() => ({}) as { verified?: boolean })
        : Promise.resolve({} as { verified?: boolean });

    const questions = buildQuestions();
    let answers: JevAnswers;
    let usage: Usage;
    let onchain: OnchainEvidence;
    let simulation: SimulationEvidence | undefined;
    let subjectVerified: boolean | undefined;
    try {
      const [call, facts, sim, intel] = await Promise.all([jev.systemOne(buildState(req, checks, feedResults), questions), onchainP, simulationP, subjectIntelP]);
      answers = call.answers;
      usage = call.usage;
      onchain = facts;
      simulation = sim;
      subjectVerified = intel.verified;
    } catch (err) {
      return fail(String(err));
    }
    // Approvals granted inside the simulated transaction to contracts: check their
    // verification too (at most two, bounded latency).
    let simSpenderUnverified = false;
    if (simulation?.status === "ok" && this.config.contractIntel) {
      const spenders = [...new Set((simulation.approvals ?? []).filter((a) => a.spender_is_contract === true).map((a) => a.spender))].slice(0, 2);
      const results = await Promise.all(spenders.map((s) => (this.config.contractIntel as ContractIntel)(s, network).catch(() => ({}) as { verified?: boolean })));
      simSpenderUnverified = results.some((r) => r.verified === false);
    }
    if (subjectVerified !== undefined) onchain = { ...onchain, verified: subjectVerified };
    if (!answersComplete(answers, questions)) return fail("jev_malformed_answers", usage);

    // Drainer-kit code fingerprints: the subject's own code, plus the called contract,
    // recipients and spenders of a simulated transaction.
    if (hasCodeFeeds(feeds)) {
      const subjectFps = fingerprintsOf(onchain.code);
      const matched = new Set<string>([...subjectFps.flatMap((fp) => matchCode(feeds, fp)), ...(simulation?.code_matches ?? []).flatMap((m) => m.sources)]);
      const scope = subjectFps.length || simulation?.code_checked ? "checked" : checks.subject.format === "evm" && onchain.status !== "ok" ? "unavailable" : "not_applicable";
      feedResults = [...feedResults, ...codeFeedResults(feeds, scope, matched)];
    }

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
    const simFindings = simulation?.findings ?? [];
    const approvalToEoa = (granting && onchain.status === "ok" && onchain.is_contract === false) || simFindings.includes("approval_to_eoa");
    if (granting && onchain.status === "ok" && onchain.is_contract === false) caps.push(onchain.activity === "none" ? APPROVAL_TO_FRESH_EOA_CAP : APPROVAL_TO_EOA_CAP);
    if (simFindings.includes("approval_to_eoa")) caps.push(APPROVAL_TO_EOA_CAP);
    // Through a source-verified forwarder (bridges such as Relay, batch senders such as
    // Disperse) an undisclosed recipient is a review item, not a drain signature.
    const verifiedForwarder = simulation?.forwarder_verified === true;
    if (simFindings.includes("outflow_to_undisclosed_eoa")) caps.push(verifiedForwarder ? VERIFIED_FORWARDER_CAP : HIDDEN_RECIPIENT_CAP);
    if (simFindings.includes("outflow_exceeds_declared")) caps.push(HIDDEN_RECIPIENT_CAP);
    if (simFindings.includes("simulation_incomplete")) caps.push(INCOMPLETE_SIMULATION_CAP);
    if (simFindings.includes("outflow_to_unverified_contract")) caps.push(UNVERIFIED_SINK_CAP);
    if (simFindings.includes("known_drainer_code")) caps.push(DRAINER_CODE_CAP);
    const unverifiedContract = (granting && onchain.is_contract === true && subjectVerified === false) || simSpenderUnverified;
    if (unverifiedContract) caps.push(UNVERIFIED_SPENDER_CAP);
    // Fail-closed: a check that should have run but failed transiently is never read as clear.
    // An approval whose spender could not be classified, or a transaction whose simulation
    // failed, gets at least review (medium). "unsupported" (a known coverage gap) does not.
    const unavailable = [
      ...(granting && onchain.status === "unavailable" ? ["onchain_unavailable"] : []),
      ...(req.transaction && simulation?.status === "unavailable" ? ["simulation_unavailable"] : []),
    ];
    const breakdown = computeScore(inputs, undefined, {
      callerFlagged,
      impersonation,
      ...(caps.length ? { evidenceCap: Math.min(...caps) } : {}),
      ...(unverifiedContract || unavailable.length || simFindings.includes("simulation_incomplete") || (verifiedForwarder && simFindings.includes("outflow_to_undisclosed_eoa")) ? { reviewFloor: true } : {}),
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
        drainerCode: hits.some((h) => h.kind === "code") || simFindings.includes("known_drainer_code"),
        approvalToEoa,
        unverifiedContract,
        simulationFindings: simFindings,
        unavailableChecks: unavailable,
      }),
      model: QUESTION_SET_VERSION,
    };
    return this.attest(req, checks, onchain, feedResults, verdict, Object.keys(questions), answers, usage, started, simulation);
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
    simulation?: SimulationEvidence,
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
      transaction: req.transaction
        ? {
            from: req.transaction.from.toLowerCase(),
            to: req.transaction.to?.toLowerCase() ?? null,
            value: req.transaction.value ? BigInt(req.transaction.value).toString() : "0",
            data_sha256: createHash("sha256").update((req.transaction.data ?? "0x").toLowerCase()).digest("hex"),
          }
        : null,
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
    const evidence: Evidence = { sanctions, ...(domain ? { domain } : {}), onchain, ...(feeds.length ? { feeds } : {}), ...(simulation ? { simulation } : {}), model: verdict.model };
    const signedChecks: AttestationChecks = {
      sanctions: { list: sanctions.list, as_of: sanctions.as_of, status: sanctions.status },
      ...(domain ? { domain: { host: domain.host, impersonation: domain.impersonation } } : {}),
      onchain: { status: onchain.status, ...(onchain.network ? { network: onchain.network } : {}), ...(onchain.activity ? { activity: onchain.activity } : {}) },
      ...(feeds.length ? { feeds: feeds.map((f) => `${f.source}@${f.as_of || "n/a"}:${f.status}`) } : {}),
      ...(simulation
        ? { simulation: { status: simulation.status, ...(simulation.network ? { network: simulation.network } : {}), ...(simulation.findings?.length ? { findings: simulation.findings } : {}) } }
        : {}),
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
      ...(req.request_hash ? { request_hash: req.request_hash } : {}),
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

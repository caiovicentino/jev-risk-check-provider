import { inputHash, signJws, type KeyPair } from "./jws.js";
import { buildQuestions, buildState, QUESTION_SET_VERSION, type JevAnswers, type JevLike, type Usage } from "./jev.js";
import { categoriesFor, computeScore, extractInputs } from "./scoring.js";
import type {
  Answer,
  RiskCheckDiscovery,
  RiskCheckRequest,
  RiskCheckResult,
} from "./types.js";

export const PROVIDER_DID_PREFIX = "did:web:";
export const ATTESTATION_TTL_MS = 60 * 60 * 1000;

export type ProviderConfig = {
  host: string;
  keyPair: KeyPair;
  jev: JevLike | null;
};

export type ScoredEvaluation = {
  result: RiskCheckResult;
  answers: JevAnswers | null;
  latencyMs: number;
  usage: Usage | null;
  error: string | null;
};

export function discoveryDocument(host: string): RiskCheckDiscovery {
  return {
    name: "JEV Risk Check Provider (paysol)",
    version: "0.1.0",
    description:
      "Typed-decision counterparty risk scoring for x402 agent commerce, powered by the TypeSafe Jev System One model.",
    endpoint: "/v1/risk-check",
    batch_endpoint: "/v1/risk-check/batch",
    method: "POST",
    signals: ["wallet", "domain", "operation_context"],
    chains_supported: ["solana", "base", "ethereum"],
    response_time_ms: "<3000",
    attestation: {
      jwks_url: `${schemeForHost(host)}://${host}/.well-known/jwks.json`,
      algorithm: "ES256",
      kid: "jev-attest-v1",
      ttl: "1h",
    },
  };
}

export function schemeForHost(host: string): string {
  return host.startsWith("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
}

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
    const jev = this.config.jev;
    if (!jev) {
      return {
        result: { checked: false },
        answers: null,
        latencyMs: Date.now() - started,
        usage: null,
        error: "jev_unconfigured",
      };
    }

    const state = buildState(req);
    const questions = buildQuestions();
    let answers: JevAnswers;
    let usage: Usage;
    try {
      const call = await jev.systemOne(state, questions);
      answers = call.answers;
      usage = call.usage;
    } catch (err) {
      return {
        result: { checked: false },
        answers: null,
        latencyMs: Date.now() - started,
        usage: null,
        error: String(err),
      };
    }

    const inputs = extractInputs(req, answers as Record<string, Answer>);
    const breakdown = computeScore(inputs, undefined, req.screening?.sanctions === "clean", req.authorization?.pre_authorized === true);
    const now = Date.now();
    const checkedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ATTESTATION_TTL_MS).toISOString();
    const hash = inputHash({
      version: QUESTION_SET_VERSION,
      wallet: req.wallet,
      chain: req.chain ?? "unknown",
      domain: req.domain ?? null,
      context: req.context ?? null,
      questions: Object.keys(questions),
    });

    const claims = {
      iss: `${PROVIDER_DID_PREFIX}${this.config.host}`,
      sub: req.wallet,
      score: breakdown.score,
      tier: breakdown.tier,
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + ATTESTATION_TTL_MS) / 1000),
      categories: categoriesFor(inputs),
      input_hash: hash,
      ...(req.aud ? { aud: req.aud } : {}),
    };

    const jws = signJws(claims, this.config.keyPair.publicJwk.kid, this.config.keyPair.privatePem);

    return {
      result: {
        checked: true,
        score: breakdown.score,
        tier: breakdown.tier,
        provider: claims.iss,
        categories: claims.categories,
        jws,
        jwks_url: this.jwksUrl,
        checked_at: checkedAt,
        expires_at: expiresAt,
      },
      answers,
      latencyMs: Date.now() - started,
      usage,
      error: null,
    };
  }
}
